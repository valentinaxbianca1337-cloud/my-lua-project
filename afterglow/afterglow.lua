package.preload["lib/memory"] = function(...)

    local ffi = require("ffi")
    local bit = require("bit")
    local band, bor, bxor, lshift, rshift, tobit = bit.band, bit.bor, bit.bxor, bit.lshift, bit.rshift, bit.tobit
    local floor = math.floor
    
    pcall(ffi.cdef, [[
        typedef unsigned char uint8_t;
        typedef unsigned short uint16_t;
        typedef unsigned int uint32_t;
        typedef int int32_t;
        typedef uintptr_t size_t;
    ]])
    
    local memory = {}
    
    function memory.address(value)
        if value == nil then return 0 end
        if type(value) == "number" then return value end
        return tonumber(ffi.cast("uintptr_t", value)) or 0
    end
    
    function memory.signature(module_name, pattern)
        local ptr = client.find_signature(module_name, pattern)
        if not ptr then
            error("memory: cannot find signature in " .. tostring(module_name), 2)
        end
        return memory.address(ptr)
    end
    
    local jmp_ecx_thunk = memory.signature("engine.dll", "\xFF\xE1")
    local get_proc_sig = memory.signature("engine.dll", "\xFF\x15\xCC\xCC\xCC\xCC\xA3\xCC\xCC\xCC\xCC\xEB\x05")
    local get_mod_sig = memory.signature("engine.dll", "\xFF\x15\xCC\xCC\xCC\xCC\x85\xC0\x74\x0B")
    
    local get_proc_target = ffi.cast("void***", get_proc_sig + 2)[0][0]
    local get_mod_target = ffi.cast("void***", get_mod_sig + 2)[0][0]
    
    local call_get_mod = ffi.cast("uintptr_t(__fastcall*)(void*, void*, const char*)", jmp_ecx_thunk)
    local call_get_proc = ffi.cast("uintptr_t(__fastcall*)(void*, void*, uintptr_t, const char*)", jmp_ecx_thunk)
    
    local kernel32_handle = call_get_mod(get_mod_target, nil, "kernel32.dll")
    local load_lib_addr = call_get_proc(get_proc_target, nil, kernel32_handle, "LoadLibraryA")
    local call_load_lib = ffi.cast("uintptr_t(__fastcall*)(uintptr_t, uintptr_t, const char*)", jmp_ecx_thunk)
    
    local function resolve_module(name)
        local h = tonumber(call_get_mod(get_mod_target, nil, name))
        if h == nil or h == 0 then
            h = tonumber(call_load_lib(load_lib_addr, 0, name))
        end
        if h == nil or h == 0 then
            error("memory: module is not loaded: " .. tostring(name), 3)
        end
        return h
    end
    
    function memory.bind(module_name, proc_name, ret_type, arg_types)
        local h = resolve_module(module_name)
        local addr = tonumber(call_get_proc(get_proc_target, nil, h, proc_name))
        if addr == nil or addr == 0 then
            error("memory: cannot resolve " .. tostring(module_name) .. "!" .. tostring(proc_name), 2)
        end
        local args_str = ""
        if type(arg_types) == "table" and #arg_types > 0 then
            args_str = ", " .. table.concat(arg_types, ", ")
        elseif type(arg_types) == "string" and #arg_types > 0 then
            args_str = ", " .. arg_types
        end
        local ctype_str = string.format("%s(__fastcall*)(uintptr_t, uintptr_t%s)", ret_type or "uintptr_t", args_str)
        local fn = ffi.cast(ctype_str, jmp_ecx_thunk)
        return function(...)
            return fn(addr, 0, ...)
        end, addr
    end
    
    local virtual_alloc = memory.bind("kernel32.dll", "VirtualAlloc", "uintptr_t", {"uintptr_t", "uintptr_t", "uint32_t", "uint32_t"})
    local virtual_free = memory.bind("kernel32.dll", "VirtualFree", "int", {"uintptr_t", "uintptr_t", "uint32_t"})
    local virtual_protect = memory.bind("kernel32.dll", "VirtualProtect", "int", {"uintptr_t", "uintptr_t", "uint32_t", "uint32_t*"})
    local get_current_process = memory.bind("kernel32.dll", "GetCurrentProcess", "uintptr_t", {})
    local flush_icache = memory.bind("kernel32.dll", "FlushInstructionCache", "int", {"uintptr_t", "uintptr_t", "uintptr_t"})
    
    function memory.flush(address, size)
        local addr = memory.address(address)
        return tonumber(flush_icache(get_current_process(), addr, size)) ~= 0
    end
    
    local Region = {}
    Region.__index = Region
    
    function Region:at(offset)
        return self.address + (offset or 0)
    end
    
    function Region:ptr(ctype, offset)
        return ffi.cast(ctype, self.address + (offset or 0))
    end
    
    function Region:write(offset, data, size, options)
        local dst = self.address + (offset or 0)
        if type(data) == "string" then
            size = size or #data
            ffi.copy(ffi.cast("void*", dst), data, size)
        elseif type(data) == "table" then
            size = size or #data
            local p = ffi.cast("uint8_t*", dst)
            for i = 1, size do p[i - 1] = data[i] end
        else
            ffi.copy(ffi.cast("void*", dst), data, size)
        end
        if not options or options.flush ~= false then
            memory.flush(dst, size)
        end
        return dst
    end
    
    local Scope = {}
    Scope.__index = Scope
    
    function memory.scope(name)
        return setmetatable({
            name = name or "memory scope",
            allocations = {},
            patches = {},
            deferred = {},
            closed = false,
            close_ok = true,
            cleanup_errors = {}
        }, Scope)
    end
    
    function Scope:alloc(size, options)
        options = options or {}
        local addr = tonumber(virtual_alloc(0, size, 0x3000, 0x40))
        if addr == nil or addr == 0 then
            error("memory: VirtualAlloc failed for " .. tostring(self.name), 2)
        end
        if options.fill ~= nil then
            ffi.fill(ffi.cast("void*", addr), size, options.fill)
        end
        local reg = setmetatable({ address = addr, size = size, freed = false }, Region)
        self.allocations[#self.allocations + 1] = reg
        return reg
    end
    
    function Scope:defer(fn)
        self.deferred[#self.deferred + 1] = fn
        return fn
    end
    
    function Scope:guard(fn, on_error)
        return function(...)
            local ok, err = pcall(fn, ...)
            if not ok then
                local close_ok, cleanup_errors = self:close()
                if on_error then
                    pcall(on_error, err, close_ok, cleanup_errors)
                end
            end
        end
    end
    
    local function write_protected(address, bytes_ptr, size)
        local old_prot = ffi.new("uint32_t[1]")
        if tonumber(virtual_protect(address, size, 0x40, old_prot)) == 0 then
            return false
        end
        ffi.copy(ffi.cast("void*", address), bytes_ptr, size)
        virtual_protect(address, size, old_prot[0], old_prot)
        memory.flush(address, size)
        return true
    end
    
    function Scope:install(address, data, options)
        local addr = memory.address(address)
        local size
        local src_ptr
        if type(data) == "string" then
            size = #data
            src_ptr = ffi.new("uint8_t[?]", size)
            ffi.copy(src_ptr, data, size)
        else
            size = ffi.sizeof(data)
            src_ptr = ffi.new("uint8_t[?]", size)
            ffi.copy(src_ptr, data, size)
        end
        local orig = ffi.new("uint8_t[?]", size)
        ffi.copy(orig, ffi.cast("const void*", addr), size)
        if not write_protected(addr, src_ptr, size) then
            error("memory: VirtualProtect failed before writing", 2)
        end
        self.patches[#self.patches + 1] = { address = addr, original = orig, replacement = src_ptr, size = size }
        return true
    end
    
    function Scope:hook_jump(site, target, size, options)
        local addr = memory.address(site)
        local dst = memory.address(target)
        size = size or 5
        local buf = ffi.new("uint8_t[?]", size)
        buf[0] = 0xE9
        local rel = tobit(dst - (addr + 5))
        ffi.cast("int32_t*", buf + 1)[0] = rel
        for i = 5, size - 1 do
            buf[i] = 0x90
        end
        return self:install(addr, buf, options)
    end
    
    function Scope:close()
        if self.closed then
            return self.close_ok, self.cleanup_errors
        end
        self.closed = true
        local errors = {}
    
        for i = #self.deferred, 1, -1 do
            local ok, res, detail = pcall(self.deferred[i])
            if not ok then
                errors[#errors + 1] = tostring(res)
            elseif res == false then
                errors[#errors + 1] = tostring(detail or "cleanup operation returned false")
            end
        end
    
        for i = #self.patches, 1, -1 do
            local p = self.patches[i]
            write_protected(p.address, p.original, p.size)
        end
        self.patches = {}
    
        if #errors == 0 then
            for i = #self.allocations, 1, -1 do
                local a = self.allocations[i]
                if not a.freed then
                    virtual_free(a.address, 0, 0x8000)
                    a.freed = true
                end
            end
            self.allocations = {}
        end
    
        self.cleanup_errors = errors
        self.close_ok = (#errors == 0)
        return self.close_ok, self.cleanup_errors
    end
    
    local REG32 = { eax = 0, ecx = 1, edx = 2, ebx = 3, esp = 4, ebp = 5, esi = 6, edi = 7 }
    local REG8 = { al = 0, cl = 1, dl = 2, bl = 3, ah = 4, ch = 5, dh = 6, bh = 7 }
    local XMM = { xmm0 = 0, xmm1 = 1, xmm2 = 2, xmm3 = 3, xmm4 = 4, xmm5 = 5, xmm6 = 6, xmm7 = 7 }
    local JCC_OP = { je = 0x84, jne = 0x85, ja = 0x87, jl = 0x8C, jge = 0x8D, jle = 0x8E, jg = 0x8F }
    
    local Assembler = {}
    Assembler.__index = Assembler
    
    function memory.assembler(symbols)
        return setmetatable({
            symbols = symbols or {},
            bytes = {},
            labels = {},
            fixups = {}
        }, Assembler)
    end
    
    function Assembler:_emit(...)
        local n = select("#", ...)
        for i = 1, n do
            local b = select(i, ...)
            self.bytes[#self.bytes + 1] = band(b, 0xFF)
        end
    end
    
    function Assembler:_emit_u32(val)
        local v = tobit(val or 0)
        self:_emit(band(v, 0xFF), band(rshift(v, 8), 0xFF), band(rshift(v, 16), 0xFF), band(rshift(v, 24), 0xFF))
    end
    
    function Assembler:_resolve_sym(val)
        if type(val) == "string" then
            if self.symbols[val] ~= nil then
                return memory.address(self.symbols[val]), true
            end
            return nil, false
        elseif type(val) == "table" and val.__imm then
            local s = val.sym
            if type(s) == "string" and self.symbols[s] ~= nil then
                return memory.address(self.symbols[s]), true
            elseif type(s) == "number" then
                return s, true
            end
        elseif type(val) == "number" then
            return val, true
        end
        return nil, false
    end
    
    function Assembler:imm(sym)
        return { __imm = true, sym = sym }
    end
    
    function Assembler:m8(base, disp)
        return self:_mem(8, base, disp)
    end
    
    function Assembler:m32(base, disp)
        return self:_mem(32, base, disp)
    end
    
    function Assembler:m128(base, disp)
        return self:_mem(128, base, disp)
    end
    
    function Assembler:_mem(bits, base, disp)
        if type(base) == "table" then
            return {
                __mem = true,
                bits = bits,
                base = base.base,
                index = base.index,
                scale = base.scale or 1,
                disp = base.disp or 0
            }
        end
        if REG32[base] ~= nil then
            return { __mem = true, bits = bits, base = base, disp = disp or 0 }
        end
        local addr, ok = self:_resolve_sym(base)
        if not ok then
            error("memory: unknown symbol " .. tostring(base), 3)
        end
        return { __mem = true, bits = bits, abs = addr + (disp or 0) }
    end
    
    function Assembler:_emit_modrm(reg_or_op, mem)
        local r = band(reg_or_op, 7)
        if mem.abs ~= nil then
            self:_emit(bor(lshift(0, 6), lshift(r, 3), 5))
            self:_emit_u32(mem.abs)
            return
        end
        local base_r = REG32[mem.base]
        local idx_r = mem.index and REG32[mem.index] or nil
        local disp = mem.disp or 0
        local mod
        if disp == 0 and base_r ~= 5 then
            mod = 0
        elseif disp >= -128 and disp <= 127 then
            mod = 1
        else
            mod = 2
        end
    
        if idx_r ~= nil or base_r == 4 then
            local scale_bits = 0
            if mem.scale == 2 then scale_bits = 1
            elseif mem.scale == 4 then scale_bits = 2
            elseif mem.scale == 8 then scale_bits = 3 end
            local sib_idx = idx_r or 4
            self:_emit(bor(lshift(mod, 6), lshift(r, 3), 4))
            self:_emit(bor(lshift(scale_bits, 6), lshift(sib_idx, 3), base_r))
        else
            self:_emit(bor(lshift(mod, 6), lshift(r, 3), base_r))
        end
    
        if mod == 1 then
            self:_emit(disp)
        elseif mod == 2 then
            self:_emit_u32(disp)
        end
    end
    
    function Assembler:label(name)
        self.labels[name] = #self.bytes
    end
    
    function Assembler:push(op)
        if type(op) == "string" and REG32[op] then
            self:_emit(0x50 + REG32[op])
        elseif type(op) == "table" and op.__mem then
            self:_emit(0xFF)
            self:_emit_modrm(6, op)
        else
            local v, ok = self:_resolve_sym(op)
            if not ok then error("memory: invalid push operand", 2) end
            if type(op) == "number" and v >= -128 and v <= 127 then
                self:_emit(0x6A, v)
            else
                self:_emit(0x68)
                self:_emit_u32(v)
            end
        end
    end
    
    function Assembler:pop(op)
        if type(op) == "string" and REG32[op] then
            self:_emit(0x58 + REG32[op])
        elseif type(op) == "table" and op.__mem then
            self:_emit(0x8F)
            self:_emit_modrm(0, op)
        end
    end
    
    function Assembler:pushad() self:_emit(0x60) end
    function Assembler:popad() self:_emit(0x61) end
    function Assembler:pushfd() self:_emit(0x9C) end
    function Assembler:popfd() self:_emit(0x9D) end
    
    function Assembler:ret(imm16)
        if not imm16 or imm16 == 0 then
            self:_emit(0xC3)
        else
            self:_emit(0xC2, band(imm16, 0xFF), band(rshift(imm16, 8), 0xFF))
        end
    end
    
    function Assembler:inc(reg) self:_emit(0x40 + REG32[reg]) end
    function Assembler:dec(reg) self:_emit(0x48 + REG32[reg]) end
    
    function Assembler:sar(reg, count)
        if count == 1 then
            self:_emit(0xD1, bor(0xC0, lshift(7, 3), REG32[reg]))
        else
            self:_emit(0xC1, bor(0xC0, lshift(7, 3), REG32[reg]), count)
        end
    end
    
    function Assembler:mov(dst, src)
        if type(dst) == "string" and REG32[dst] then
            local dr = REG32[dst]
            if type(src) == "string" and REG32[src] then
                self:_emit(0x89, bor(0xC0, lshift(REG32[src], 3), dr))
            elseif type(src) == "table" and src.__mem then
                self:_emit(0x8B)
                self:_emit_modrm(dr, src)
            else
                local v, ok = self:_resolve_sym(src)
                if not ok then error("memory: invalid mov imm", 2) end
                self:_emit(0xB8 + dr)
                self:_emit_u32(v)
            end
        elseif type(dst) == "table" and dst.__mem then
            if dst.bits == 8 then
                if type(src) == "string" and REG8[src] then
                    self:_emit(0x88)
                    self:_emit_modrm(REG8[src], dst)
                else
                    local v = self:_resolve_sym(src)
                    self:_emit(0xC6)
                    self:_emit_modrm(0, dst)
                    self:_emit(v)
                end
            else
                if type(src) == "string" and REG32[src] then
                    self:_emit(0x89)
                    self:_emit_modrm(REG32[src], dst)
                else
                    local v = self:_resolve_sym(src)
                    self:_emit(0xC7)
                    self:_emit_modrm(0, dst)
                    self:_emit_u32(v)
                end
            end
        end
    end
    
    function Assembler:movzx(dst, src)
        local dr = REG32[dst]
        self:_emit(0x0F, 0xB6)
        self:_emit_modrm(dr, src)
    end
    
    function Assembler:movss(dst, src)
        local xr = XMM[dst]
        self:_emit(0xF3, 0x0F, 0x10)
        self:_emit_modrm(xr, src)
    end
    
    function Assembler:movups(dst, src)
        if type(dst) == "string" and XMM[dst] then
            self:_emit(0x0F, 0x10)
            self:_emit_modrm(XMM[dst], src)
        else
            self:_emit(0x0F, 0x11)
            self:_emit_modrm(XMM[src], dst)
        end
    end
    
    function Assembler:_alu(op_idx, dst, src)
        local base_op = op_idx * 8
        if type(dst) == "string" and REG32[dst] then
            local dr = REG32[dst]
            if type(src) == "string" and REG32[src] then
                self:_emit(base_op + 1, bor(0xC0, lshift(REG32[src], 3), dr))
            elseif type(src) == "table" and src.__mem then
                self:_emit(base_op + 3)
                self:_emit_modrm(dr, src)
            else
                local v = self:_resolve_sym(src)
                if type(src) == "number" and v >= -128 and v <= 127 then
                    self:_emit(0x83, bor(0xC0, lshift(op_idx, 3), dr), v)
                else
                    self:_emit(0x81, bor(0xC0, lshift(op_idx, 3), dr))
                    self:_emit_u32(v)
                end
            end
        elseif type(dst) == "table" and dst.__mem then
            if dst.bits == 8 then
                local v = self:_resolve_sym(src)
                self:_emit(0x80)
                self:_emit_modrm(op_idx, dst)
                self:_emit(v)
            elseif type(src) == "string" and REG32[src] then
                self:_emit(base_op + 1)
                self:_emit_modrm(REG32[src], dst)
            else
                local v = self:_resolve_sym(src)
                if type(src) == "number" and v >= -128 and v <= 127 then
                    self:_emit(0x83)
                    self:_emit_modrm(op_idx, dst)
                    self:_emit(v)
                else
                    self:_emit(0x81)
                    self:_emit_modrm(op_idx, dst)
                    self:_emit_u32(v)
                end
            end
        end
    end
    
    function Assembler:add(dst, src) self:_alu(0, dst, src) end
    function Assembler:or_(dst, src) self:_alu(1, dst, src) end
    function Assembler:and_(dst, src) self:_alu(4, dst, src) end
    function Assembler:sub(dst, src) self:_alu(5, dst, src) end
    function Assembler:xor_(dst, src) self:_alu(6, dst, src) end
    function Assembler:cmp(dst, src) self:_alu(7, dst, src) end
    
    function Assembler:test(dst, src)
        local dr = REG32[dst]
        if type(src) == "string" and REG32[src] then
            self:_emit(0x85, bor(0xC0, lshift(REG32[src], 3), dr))
        else
            local v = self:_resolve_sym(src)
            self:_emit(0xF7, bor(0xC0, lshift(0, 3), dr))
            self:_emit_u32(v)
        end
    end
    
    function Assembler:call(target)
        if type(target) == "string" and REG32[target] then
            self:_emit(0xFF, bor(0xC0, lshift(2, 3), REG32[target]))
        elseif type(target) == "table" and target.__mem then
            self:_emit(0xFF)
            self:_emit_modrm(2, target)
        else
            local v = self:_resolve_sym(target)
            self:_emit(0xE8)
            self.fixups[#self.fixups + 1] = { pos = #self.bytes + 1, target = v, absolute = true }
            self:_emit_u32(0)
        end
    end
    
    function Assembler:jmp(target)
        self:_emit(0xE9)
        if type(target) == "number" then
            self.fixups[#self.fixups + 1] = { pos = #self.bytes + 1, target = target, absolute = true }
        else
            self.fixups[#self.fixups + 1] = { pos = #self.bytes + 1, label = target }
        end
        self:_emit_u32(0)
    end
    
    for mnem, opcode in pairs(JCC_OP) do
        Assembler[mnem] = function(self, target)
            self:_emit(0x0F, opcode)
            self.fixups[#self.fixups + 1] = { pos = #self.bytes + 1, label = target }
            self:_emit_u32(0)
        end
    end
    
    function Assembler:finish(base_address)
        local base = memory.address(base_address)
        for i = 1, #self.fixups do
            local fx = self.fixups[i]
            local pos = fx.pos
            local next_ip = base + pos + 3
            local target_addr
            if fx.absolute then
                target_addr = fx.target
            else
                local lbl_off = self.labels[fx.label]
                if lbl_off == nil then
                    error("memory: missing assembler label " .. tostring(fx.label), 2)
                end
                target_addr = base + lbl_off
            end
            local rel = tobit(target_addr - next_ip)
            self.bytes[pos]     = band(rel, 0xFF)
            self.bytes[pos + 1] = band(rshift(rel, 8), 0xFF)
            self.bytes[pos + 2] = band(rshift(rel, 16), 0xFF)
            self.bytes[pos + 3] = band(rshift(rel, 24), 0xFF)
        end
        local size = #self.bytes
        local buf = ffi.new("uint8_t[?]", size)
        for i = 1, size do
            buf[i - 1] = self.bytes[i]
        end
        return buf, size
    end
    
    return memory
    
    end
    
    package.preload["lib/custom_tab"] = function(...)
    
    local ffi = require("ffi")
    local memory = require("lib/memory")
    
    local SCRIPT_NAME = "Custom native GUI tab library"
    local VERSION = "2.8.1"
    local TWO32 = 0x100000000
    
    local ADDRESS = {
        menu = 0x43476924,
        allocator = 0x43387448,
        string_ctor = 0x433B3313,
        string_release = 0x43336BC2,
        tab_ctor = 0x4348E41D,
        category_ctor = 0x4348210C,
        add_child = 0x4347DE9B,
        layout = 0x43384477,
        full_layout = 0x433CCAE7,
        category_reflow = 0x433AD23F,
        listbox_reflow = 0x4339E4DF,
        dpi_refresh = 0x4339F0AD,
        tab_vtable = 0x4346F9C8,
        tab_render = 0x433AC635,
        tab_reset = 0x43340044,
        category_vtable = 0x4347072C,
        category_render = 0x433AE90F,
        button_vtable = 0x4346F134,
        button_render = 0x43359006,
        gui_renderer_vtable = 0x43472A80,
        gui_dpi_scale = 0x4346D490
    }
    
    local MENU = {
        x = 0x0C,
        y = 0x10,
        width = 0x14,
        height = 0x18,
        tabs_begin = 0x54,
        tabs_end = 0x58,
        tabs_capacity = 0x5C,
        active = 0x64
    }
    
    local CONTROL = {
        parent = 0x10,
        visible = 0x15,
        type = 0x19,
        x = 0x20,
        y = 0x24,
        width = 0x28,
        height = 0x2C,
        intrinsic_height = 0x34,
        title = 0x38,
        title_owner = 0x3C,
        clip_overlap = 0x1A,
        listbox_row_height = 0x60,
        listbox_header = 0x7C,
        listbox_items_begin = 0xB0,
        listbox_items_end = 0xB4
    }
    
    local TAB = {
        index = 0x0C,
        visible = 0x15,
        hover = 0x16,
        x = 0x20,
        y = 0x24,
        width = 0x28,
        height = 0x2C,
        title = 0x38,
        title_owner = 0x3C,
        parent = 0x60,
        children_begin = 0x70,
        children_end = 0x74,
        children_capacity = 0x78,
        icon = 0x80,
        icon_u = 0x84,
        icon_v = 0x88,
        icon_width = 0x8C,
        icon_height = 0x90
    }
    
    local CATEGORY = {
        parent = 0x10,
        visible = 0x15,
        title = 0x38,
        title_owner = 0x3C,
        grid = 0x70,
        controls_begin = 0x80,
        controls_end = 0x84,
        controls_capacity = 0x88,
        layout_mode = 0x7C,
        layout_editable = 0xB0
    }
    
    local OBJECT_SIZE = {
        tab = 0x98,
        category = 0xC8,
        tab_vtable = 0x88,
        category_vtable = 0x34,
        button_vtable = 0x34
    }
    local TAB_VTABLE_SLOT_REGION = 0x80
    local TAB_VTABLE_METADATA = 0x80
    
    local NATIVE_TAB_VTABLE_SIZES = {
        [0x4346ED5C] = 0x3C,
        [0x4346F6DC] = 0x3C,
        [0x4346F9C8] = 0x60,
        [0x43470094] = 0x7C,
        [0x43470684] = 0x3C,
        [0x434706C8] = 0x3C,
        [0x43471FCC] = 0x3C
    }
    local CLIPPED_TAB_VTABLE_MAGIC = 0x43544350
    local CUSTOM_TAB_VTABLE_MAGIC = 0x43544355
    local CLIPPED_TAB_VTABLE_SIZE = 0x88
    
    local MAX_CATEGORIES = 64
    local MAX_BUTTON_ICONS = 128
    local BUTTON_TYPE = 0x02
    local LISTBOX_TYPE = 0x06
    local LISTBOX_ITEM_INDEX_SIZE = 2
    local DEFAULT_EMBEDDED_ICON_SIZE = 16
    local DEFAULT_ICON = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\csgo legacy\\etools\\Medkit.png"
    local PNG_SIGNATURE = "\137PNG\r\n\26\n"
    local GUI_DPI_SCALES = {
        [1.00] = true,
        [1.25] = true,
        [1.50] = true,
        [1.75] = true,
        [2.00] = true
    }
    
    local CAVE = {
        size = 0xC00,
        state = 0x000,
        alloc = 0x040,
        tab_ctor = 0x080,
        string_ctor = 0x0C0,
        string_release = 0x100,
        category_ctor = 0x140,
        add_child = 0x180,
        layout = 0x1C0,
        noop = 0x200,
        tab_reset = 0x240,
        full_layout = 0x2A0,
        category_reflow = 0x300,
        tab_render = 0x340,
        listbox_reflow = 0x500,
        dpi_refresh = 0x540,
        category_icon_render = 0x600,
        button_icon_render = 0xA00
    }
    
    local State = ffi.typeof([[struct {
        uint32_t custom_tab;
        int32_t icon_offset_x;
        int32_t icon_offset_y;
    }]])
    
    local IconRecord = ffi.typeof([[struct {
        uint32_t object;
        uint32_t texture;
        uint32_t source_width;
        uint32_t source_height;
        float scale;
        int32_t destination_width;
        int32_t destination_height;
        int32_t anchor_x;
        int32_t offset_x;
        int32_t offset_y;
        uint32_t color;
        uint32_t flags;
        uint32_t replacement_title;
        uint32_t replacement_owner;
        int32_t title_clip;
    }]])
    
    local IconRegistry = ffi.typeof([[struct {
        uint32_t category_count;
        uint32_t button_count;
        $ categories[64];
        $ buttons[128];
    }]], IconRecord, IconRecord)
    
    local ICON_RECORD = {
        size = ffi.sizeof(IconRecord),
        object = ffi.offsetof(IconRecord, "object"),
        texture = ffi.offsetof(IconRecord, "texture"),
        source_width = ffi.offsetof(IconRecord, "source_width"),
        source_height = ffi.offsetof(IconRecord, "source_height"),
        scale = ffi.offsetof(IconRecord, "scale"),
        destination_width = ffi.offsetof(IconRecord, "destination_width"),
        destination_height = ffi.offsetof(IconRecord, "destination_height"),
        anchor_x = ffi.offsetof(IconRecord, "anchor_x"),
        offset_x = ffi.offsetof(IconRecord, "offset_x"),
        offset_y = ffi.offsetof(IconRecord, "offset_y"),
        color = ffi.offsetof(IconRecord, "color"),
        flags = ffi.offsetof(IconRecord, "flags"),
        replacement_title = ffi.offsetof(IconRecord, "replacement_title"),
        replacement_owner = ffi.offsetof(IconRecord, "replacement_owner"),
        title_clip = ffi.offsetof(IconRecord, "title_clip")
    }
    
    local ICON_FLAG_IMAGE = 0x01
    local ICON_FLAG_HIDE_SCROLLBAR = 0x02
    local ICON_FLAG_NO_CLIP = 0x04
    
    local ICON_REGISTRY = {
        category_count = ffi.offsetof(IconRegistry, "category_count"),
        button_count = ffi.offsetof(IconRegistry, "button_count"),
        categories = ffi.offsetof(IconRegistry, "categories"),
        buttons = ffi.offsetof(IconRegistry, "buttons")
    }
    
    local floor = math.floor
    local ceil = math.ceil
    local min = math.min
    local max = math.max
    
    local lifetime
    local cave
    local native
    local handle
    local paint_installed = false
    local paint_callback
    
    local function u32(address, offset)
        return tonumber(ffi.cast("uint32_t*", address + offset)[0])
    end
    
    local function put_u32(address, offset, value)
        ffi.cast("uint32_t*", address + offset)[0] = value % TWO32
    end
    
    local function u8(address, offset)
        return tonumber(ffi.cast("uint8_t*", address + offset)[0])
    end
    
    local function put_u8(address, offset, value)
        ffi.cast("uint8_t*", address + offset)[0] = value % 0x100
    end
    
    local function is_integer(value)
        return type(value) == "number"
            and value == value
            and value ~= math.huge
            and value ~= -math.huge
            and value == floor(value)
    end
    
    local function check_name(value, level)
        if type(value) ~= "string" then
            error("custom_tab: category names must be strings", level or 2)
        end
        return value
    end
    
    local function normalize_categories(values)
        if values == nil then
            return {}
        end
        if type(values) ~= "table" then
            error("custom_tab: categories must be an array of strings or category tables", 3)
        end
        if #values > MAX_CATEGORIES then
            error("custom_tab: category limit is " .. MAX_CATEGORIES, 3)
        end
    
        local result = {}
        local definitions = {}
        for index = 1, #values do
            local value = values[index]
            if type(value) == "table" then
                definitions[index] = value
                value = value.name
            end
            result[index] = check_name(value, 3)
        end
        return result, definitions
    end
    
    local function normalize_category_layouts(values, count, level)
        if values == nil then
            return {}
        end
        if type(values) ~= "table" or #values ~= count then
            error("custom_tab: category_layouts must match the category count", level or 3)
        end
    
        local result = {}
        for index = 1, count do
            local grid = values[index]
            if not is_integer(grid) or grid < 0 or grid > 0xFFFFFFFF then
                error("custom_tab: invalid category layout grid", level or 3)
            end
            local x = grid % 0x100
            local width = floor(grid / 0x100) % 0x100
            local y = floor(grid / 0x10000) % 0x100
            local height = floor(grid / 0x1000000) % 0x100
            if width < 1 or height < 1 or x + width > 24 or y + height > 24 then
                error("custom_tab: category layout is outside the 24x24 grid", level or 3)
            end
            result[index] = grid
        end
        return result
    end
    
    local function normalize_icon_offset(value, name)
        value = value or 0
        if not is_integer(value) or value < -16 or value > 16 then
            error("custom_tab: " .. name .. " must be an integer from -16 to 16", 3)
        end
        return value
    end
    
    local function normalize_size(value, level)
        if value == nil then
            return nil, nil
        end
        if type(value) ~= "table"
            or not is_integer(value.width)
            or not is_integer(value.height)
            or value.width < 1
            or value.height < 1
            or value.width > 0x7FFFFFFF
            or value.height > 0x7FFFFFFF
        then
            error("custom_tab: size must contain positive integer width and height", level or 3)
        end
        return value.width, value.height
    end
    
    local function normalize_embedded_icon_size(value, level)
        if value == nil then
            return DEFAULT_EMBEDDED_ICON_SIZE, DEFAULT_EMBEDDED_ICON_SIZE
        end
        if is_integer(value) then
            if value < 1 or value > 64 then
                error("custom_tab: icon size must be an integer from 1 to 64", level or 3)
            end
            return value, value
        end
        if type(value) ~= "table"
            or not is_integer(value.width)
            or not is_integer(value.height)
            or value.width < 1
            or value.width > 64
            or value.height < 1
            or value.height > 64
        then
            error(
                "custom_tab: icon size must be an integer or a 1..64 width/height table",
                level or 3
            )
        end
        return value.width, value.height
    end
    
    local function normalize_embedded_icon_offset(value, name, level)
        value = value or 0
        if not is_integer(value) or value < -64 or value > 64 then
            error(
                "custom_tab: " .. name .. " must be an integer from -64 to 64",
                level or 3
            )
        end
        return value
    end
    
    local function normalize_embedded_icon(path, data, source, options, level)
        options = options or {}
        if type(options) ~= "table" then
            error("custom_tab: icon options must be a table", level or 3)
        end
        if options.text ~= nil or options.name ~= nil then
            error("custom_tab: embedded icons are icon-only; remove text/name", level or 3)
        end
        if (path == nil) == (data == nil) then
            error("custom_tab: provide exactly one PNG path or PNG data value", level or 3)
        end
        if path ~= nil and (type(path) ~= "string" or #path == 0) then
            error("custom_tab: icon path must be a non-empty string", level or 3)
        end
        if data ~= nil and (type(data) ~= "string" or #data == 0) then
            error("custom_tab: icon data must be a non-empty string", level or 3)
        end
        source = source or path or "<memory>"
        if type(source) ~= "string" or #source == 0 then
            error("custom_tab: icon source must be a non-empty string", level or 3)
        end
    
        local box_width, box_height = normalize_embedded_icon_size(
            options.size or options.icon_size,
            level or 3
        )
        return {
            icon_path = source,
            icon_data = data,
            box_width = box_width,
            box_height = box_height,
            offset_x = normalize_embedded_icon_offset(
                options.offset_x or options.icon_offset_x,
                "icon offset_x",
                level or 3
            ),
            offset_y = normalize_embedded_icon_offset(
                options.offset_y or options.icon_offset_y,
                "icon offset_y",
                level or 3
            ),
            texture = nil,
            texture_source_width = nil,
            texture_source_height = nil,
            texture_cache = {}
        }
    end
    
    local function category_icon_from_definition(definition, level)
        if definition == nil then
            return nil
        end
        local path = definition.icon
        local data = definition.icon_data
        if path == nil and data == nil then
            return nil
        end
        return normalize_embedded_icon(
            path,
            data,
            definition.icon_source,
            {
                icon_size = definition.icon_size or definition.size,
                icon_offset_x = definition.icon_offset_x,
                icon_offset_y = definition.icon_offset_y
            },
            level or 3
        )
    end
    
    local POSITION_ALIASES = {
        rage = 0,
        imbot = 0,
        aa = 1,
        ["anti-aimbot angles"] = 1,
        legit = 2,
        visuals = 3,
        misc = 4,
        skins = 5,
        lua = 6
    }
    
    local function normalize_position(value)
        if value == nil or value == "after_lua" or value == "after-lua" then
            return "after_lua"
        end
        if is_integer(value) and value >= 0 then
            return value
        end
        if type(value) == "string" then
            local position = POSITION_ALIASES[value:lower()]
            if position ~= nil then
                return position
            end
        end
        error("custom_tab: invalid tab position", 3)
    end
    
    local function make_bridge(target, argument_count)
        local asm = memory.assembler()
        asm:push("ebp")
        asm:mov("ebp", "esp")
        asm:mov("ecx", asm:m32("ebp", 8))
        for index = argument_count, 2, -1 do
            asm:push(asm:m32("ebp", 4 + index * 4))
        end
        asm:mov("eax", target)
        asm:call("eax")
        asm:mov("esp", "ebp")
        asm:pop("ebp")
        asm:ret(argument_count * 4)
        return asm
    end
    
    local function make_noop_bridge()
        local asm = memory.assembler()
        asm:ret()
        return asm
    end
    
    local function make_tab_render_bridge()
        local asm = memory.assembler({
            custom_tab = cave:at(CAVE.state + ffi.offsetof(State, "custom_tab")),
            icon_offset_x = cave:at(CAVE.state + ffi.offsetof(State, "icon_offset_x")),
            icon_offset_y = cave:at(CAVE.state + ffi.offsetof(State, "icon_offset_y")),
            shared_tab_render = ADDRESS.tab_vtable + 0x10
        })
    
        asm:push("ebp")
        asm:mov("ebp", "esp")
        asm:push("ebx")
        asm:push("esi")
        asm:push("edi")
        asm:mov("esi", "ecx")
        asm:xor_("ebx", "ebx")
        asm:xor_("edi", "edi")
    
        asm:mov("eax", asm:m32("esi", TAB.parent))
        asm:mov("edx", asm:m32("esi", TAB.y))
        asm:add("edx", asm:m32("esi", TAB.height))
        asm:cmp("esi", asm:m32("custom_tab"))
        asm:jne("check_bottom")
        asm:add("edx", asm:m32("icon_offset_y"))
        asm:label("check_bottom")
        asm:cmp("edx", asm:m32("eax", 0x18))
        asm:jl("draw")
    
        asm:mov("ebx", asm:m32("esi", TAB.icon))
        asm:push(asm:m32("esi", TAB.title))
        asm:push(asm:m32("esi", TAB.title_owner))
        asm:mov(asm:m32("esi", TAB.icon), -1)
        asm:mov(asm:m32("esi", TAB.title), 0)
        asm:mov(asm:m32("esi", TAB.title_owner), 0)
        asm:inc("edi")
    
        asm:label("draw")
        asm:cmp("esi", asm:m32("custom_tab"))
        asm:jne("call_native")
        asm:mov("eax", asm:m32("icon_offset_x"))
        asm:add(asm:m32("esi", TAB.x), "eax")
        asm:mov("edx", asm:m32("icon_offset_y"))
        asm:add(asm:m32("esi", TAB.y), "edx")
        asm:push(asm:m32("ebp", 0x0C))
        asm:push(asm:m32("ebp", 0x08))
        asm:mov("ecx", "esi")
        asm:mov("eax", asm:m32("shared_tab_render"))
        asm:call("eax")
        asm:mov("eax", asm:m32("icon_offset_x"))
        asm:sub(asm:m32("esi", TAB.x), "eax")
        asm:mov("edx", asm:m32("icon_offset_y"))
        asm:sub(asm:m32("esi", TAB.y), "edx")
        asm:jmp("restore_tab")
    
        asm:label("call_native")
        asm:push(asm:m32("ebp", 0x0C))
        asm:push(asm:m32("ebp", 0x08))
        asm:mov("ecx", "esi")
        asm:mov("eax", asm:m32("shared_tab_render"))
        asm:call("eax")
    
        asm:label("restore_tab")
        asm:test("edi", "edi")
        asm:je("done")
        asm:mov(asm:m32("esi", TAB.icon), "ebx")
        asm:pop("eax")
        asm:mov(asm:m32("esi", TAB.title_owner), "eax")
        asm:pop("eax")
        asm:mov(asm:m32("esi", TAB.title), "eax")
    
        asm:label("done")
        asm:pop("edi")
        asm:pop("esi")
        asm:pop("ebx")
        asm:mov("esp", "ebp")
        asm:pop("ebp")
        asm:ret(8)
        return asm
    end
    
    local function make_category_icon_render_bridge(render_target, registry_address)
        local asm = memory.assembler({
            category_count = registry_address + ICON_REGISTRY.category_count,
            category_records = registry_address + ICON_REGISTRY.categories
        })
    
        asm:push("ebp")
        asm:mov("ebp", "esp")
        asm:sub("esp", 0x18)
        asm:push("ebx")
        asm:push("esi")
        asm:push("edi")
        asm:mov("esi", "ecx")
        asm:xor_("edi", "edi")
        asm:mov("ebx", asm:imm("category_records"))
        asm:mov("ecx", asm:m32("category_count"))
    
        asm:label("category_search")
        asm:test("ecx", "ecx")
        asm:je("category_call_native")
        asm:cmp("esi", asm:m32("ebx", ICON_RECORD.object))
        asm:je("category_found")
        asm:add("ebx", ICON_RECORD.size)
        asm:dec("ecx")
        asm:jmp("category_search")
    
        asm:label("category_found")
        asm:mov("edi", "ebx")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.flags))
        asm:test("eax", ICON_FLAG_IMAGE)
        asm:je("category_hide_scrollbar")
        asm:mov("eax", asm:m32("esi", CATEGORY.title))
        asm:mov(asm:m32("ebp", -4), "eax")
        asm:mov("eax", asm:m32("esi", CATEGORY.title_owner))
        asm:mov(asm:m32("ebp", -8), "eax")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.replacement_title))
        asm:mov(asm:m32("esi", CATEGORY.title), "eax")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.replacement_owner))
        asm:mov(asm:m32("esi", CATEGORY.title_owner), "eax")
    
        asm:label("category_hide_scrollbar")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.flags))
        asm:test("eax", ICON_FLAG_HIDE_SCROLLBAR)
        asm:je("category_call_native")
        asm:movzx("eax", asm:m8("esi", 0x94))
        asm:mov(asm:m32("ebp", -0x10), "eax")
        asm:mov("eax", asm:m32("esi", 0xA8))
        asm:mov(asm:m32("ebp", -0x14), "eax")
        asm:cmp(asm:m32("ebp", -0x10), 0)
        asm:jne("category_scroll_present")
        asm:push("eax")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.flags))
        asm:test("eax", ICON_FLAG_NO_CLIP)
        asm:pop("eax")
        asm:je("category_clear_scrollbar")
        asm:xor_("eax", "eax")
        asm:jmp("category_shift_prepare")
        asm:label("category_scroll_present")
        asm:test("eax", "eax")
        asm:jne("category_shift_prepare")
        asm:push("eax")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.flags))
        asm:test("eax", ICON_FLAG_NO_CLIP)
        asm:pop("eax")
        asm:je("category_clear_scrollbar")
        asm:label("category_shift_prepare")
        asm:mov("ebx", asm:m32("esi", CATEGORY.controls_begin))
        asm:mov("ecx", asm:m32("esi", CATEGORY.controls_end))
    
        asm:label("category_shift_controls")
        asm:cmp("ebx", "ecx")
        asm:je("category_clear_scrollbar")
        asm:mov("edx", asm:m32("ebx"))
        asm:sub(asm:m32("edx", CONTROL.y), "eax")
        asm:push("eax")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.flags))
        asm:test("eax", ICON_FLAG_NO_CLIP)
        asm:je("category_clip_check")
        asm:mov("eax", asm:m32("edx", CONTROL.y))
        asm:cmp("eax", asm:m32("edi", ICON_RECORD.title_clip))
        asm:jge("category_shift_keep")
        asm:push("ecx")
        asm:mov("ecx", asm:m32("edi", ICON_RECORD.title_clip))
        asm:sub("ecx", "eax")
        asm:cmp("ecx", 0xFF)
        asm:ja("category_noclip_pop")
        asm:mov(asm:m8("edx", CONTROL.clip_overlap), "cl")
        asm:add(asm:m32("edx", CONTROL.y), "ecx")
        asm:label("category_noclip_pop")
        asm:pop("ecx")
        asm:jmp("category_shift_keep")
        asm:label("category_clip_check")
        asm:mov("eax", asm:m32("edx", CONTROL.y))
        asm:add("eax", asm:m32("edx", CONTROL.height))
        asm:cmp("eax", asm:m32("edi", ICON_RECORD.title_clip))
        asm:jle("category_cull_shifted")
        asm:mov("eax", asm:m32("edx", CONTROL.y))
        asm:cmp("eax", asm:m32("esi", CONTROL.height))
        asm:jge("category_cull_shifted")
        asm:cmp("eax", asm:m32("edi", ICON_RECORD.title_clip))
        asm:jge("category_shift_keep")
        asm:cmp(asm:m8("edx", CONTROL.type), LISTBOX_TYPE)
        asm:jne("category_cull_shifted")
        asm:push("ecx")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.title_clip))
        asm:sub("eax", asm:m32("edx", CONTROL.y))
        asm:cmp("eax", 0xFF)
        asm:ja("category_clamp_too_tall")
        asm:mov("ecx", "eax")
        asm:mov("eax", asm:m32("edx", CONTROL.height))
        asm:cmp("eax", "ecx")
        asm:jle("category_clamp_too_tall")
        asm:sub("eax", "ecx")
        asm:mov(asm:m32("edx", CONTROL.height), "eax")
        asm:mov(asm:m8("edx", CONTROL.clip_overlap), "cl")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.title_clip))
        asm:mov(asm:m32("edx", CONTROL.y), "eax")
        asm:pop("ecx")
        asm:jmp("category_shift_keep")
        asm:label("category_clamp_too_tall")
        asm:pop("ecx")
        asm:label("category_cull_shifted")
        asm:add(asm:m32("edx", CONTROL.y), 0x100000)
        asm:label("category_shift_keep")
        asm:pop("eax")
        asm:add("ebx", 4)
        asm:jmp("category_shift_controls")
    
        asm:label("category_clear_scrollbar")
        asm:mov(asm:m8("esi", 0x94), 0)
    
        asm:label("category_call_native")
        asm:push(asm:m32("ebp", 0x0C))
        asm:push(asm:m32("ebp", 0x08))
        asm:mov("ecx", "esi")
        asm:mov("eax", render_target)
        asm:call("eax")
        asm:mov(asm:m32("ebp", -0x0C), "eax")
        asm:test("edi", "edi")
        asm:je("category_done")
    
        asm:mov("eax", asm:m32("edi", ICON_RECORD.flags))
        asm:test("eax", ICON_FLAG_HIDE_SCROLLBAR)
        asm:je("category_restore_title")
        asm:cmp(asm:m32("ebp", -0x10), 0)
        asm:jne("category_restore_flag_open")
        asm:push("eax")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.flags))
        asm:test("eax", ICON_FLAG_NO_CLIP)
        asm:pop("eax")
        asm:je("category_restore_scrollbar_flag")
        asm:xor_("eax", "eax")
        asm:jmp("category_restore_prepare")
        asm:label("category_restore_flag_open")
        asm:mov("eax", asm:m32("ebp", -0x14))
        asm:test("eax", "eax")
        asm:jne("category_restore_prepare")
        asm:push("eax")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.flags))
        asm:test("eax", ICON_FLAG_NO_CLIP)
        asm:pop("eax")
        asm:je("category_restore_scrollbar_flag")
        asm:label("category_restore_prepare")
        asm:mov("ebx", asm:m32("esi", CATEGORY.controls_begin))
        asm:mov("ecx", asm:m32("esi", CATEGORY.controls_end))
    
        asm:label("category_restore_controls")
        asm:cmp("ebx", "ecx")
        asm:je("category_restore_scrollbar_flag")
        asm:mov("edx", asm:m32("ebx"))
        asm:push("eax")
        asm:movzx("eax", asm:m8("edx", CONTROL.clip_overlap))
        asm:test("eax", "eax")
        asm:je("category_restore_unclamped")
        asm:push("eax")
        asm:mov(asm:m8("edx", CONTROL.clip_overlap), 0)
        asm:mov("eax", asm:m32("edi", ICON_RECORD.flags))
        asm:test("eax", ICON_FLAG_NO_CLIP)
        asm:jne("category_restore_noclip_y")
        asm:mov("eax", asm:m32("edx", CONTROL.height))
        asm:add("eax", asm:m32("esp"))
        asm:mov(asm:m32("edx", CONTROL.height), "eax")
        asm:label("category_restore_noclip_y")
        asm:pop("eax")
        asm:sub(asm:m32("edx", CONTROL.y), "eax")
        asm:label("category_restore_unclamped")
        asm:pop("eax")
        asm:cmp(asm:m32("edx", CONTROL.y), 0x80000)
        asm:jl("category_restore_add")
        asm:sub(asm:m32("edx", CONTROL.y), 0x100000)
        asm:label("category_restore_add")
        asm:add(asm:m32("edx", CONTROL.y), "eax")
        asm:add("ebx", 4)
        asm:jmp("category_restore_controls")
    
        asm:label("category_restore_scrollbar_flag")
        asm:mov("eax", asm:m32("ebp", -0x10))
        asm:mov(asm:m8("esi", 0x94), "al")
    
        asm:label("category_restore_title")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.flags))
        asm:test("eax", ICON_FLAG_IMAGE)
        asm:je("category_done")
    
        asm:mov("eax", asm:m32("ebp", -4))
        asm:mov(asm:m32("esi", CATEGORY.title), "eax")
        asm:mov("eax", asm:m32("ebp", -8))
        asm:mov(asm:m32("esi", CATEGORY.title_owner), "eax")
    
        asm:mov("ecx", asm:m32("ebp", 0x08))
        asm:test("ecx", "ecx")
        asm:je("category_done")
        asm:cmp(asm:m32("ecx"), ADDRESS.gui_renderer_vtable)
        asm:jne("category_done")
        asm:mov("edx", asm:m32("edi", ICON_RECORD.texture))
        asm:test("edx", "edx")
        asm:je("category_done")
    
        asm:push(0)
        asm:push(asm:m32("edi", ICON_RECORD.source_height))
        asm:push(asm:m32("edi", ICON_RECORD.source_width))
        asm:push(0)
        asm:push(0)
        asm:push(asm:m32("edi", ICON_RECORD.color))
    
        asm:mov("eax", asm:m32("ebp", 0x0C))
        asm:mov("ebx", asm:m32("eax", 4))
        asm:add("ebx", asm:m32("esi", CONTROL.y))
        asm:mov("eax", asm:m32("edi", ICON_RECORD.destination_height))
        asm:sar("eax", 1)
        asm:sub("ebx", "eax")
        asm:add("ebx", asm:m32("edi", ICON_RECORD.offset_y))
        asm:push("ebx")
    
        asm:mov("eax", asm:m32("ebp", 0x0C))
        asm:mov("ebx", asm:m32("eax"))
        asm:add("ebx", asm:m32("esi", CONTROL.x))
        asm:add("ebx", 14)
        asm:add("ebx", asm:m32("edi", ICON_RECORD.anchor_x))
        asm:add("ebx", asm:m32("edi", ICON_RECORD.offset_x))
        asm:push("ebx")
    
        asm:mov("edx", asm:m32("edi", ICON_RECORD.texture))
        asm:movss("xmm0", asm:m32("edi", ICON_RECORD.scale))
        asm:mov("ecx", asm:m32("ebp", 0x08))
        asm:mov("eax", asm:m32("ecx"))
        asm:call(asm:m32("eax", 0x5C))
    
        asm:label("category_done")
        asm:mov("eax", asm:m32("ebp", -0x0C))
        asm:pop("edi")
        asm:pop("esi")
        asm:pop("ebx")
        asm:mov("esp", "ebp")
        asm:pop("ebp")
        asm:ret(8)
        return asm
    end
    
    local function make_button_icon_render_bridge(render_target, registry_address)
        local asm = memory.assembler({
            button_count = registry_address + ICON_REGISTRY.button_count,
            button_records = registry_address + ICON_REGISTRY.buttons
        })
    
        asm:push("ebp")
        asm:mov("ebp", "esp")
        asm:sub("esp", 0x0C)
        asm:push("ebx")
        asm:push("esi")
        asm:push("edi")
        asm:mov("esi", "ecx")
        asm:xor_("edi", "edi")
        asm:mov("ebx", asm:imm("button_records"))
        asm:mov("ecx", asm:m32("button_count"))
    
        asm:label("button_search")
        asm:test("ecx", "ecx")
        asm:je("button_call_native")
        asm:cmp("esi", asm:m32("ebx", ICON_RECORD.object))
        asm:je("button_found")
        asm:add("ebx", ICON_RECORD.size)
        asm:dec("ecx")
        asm:jmp("button_search")
    
        asm:label("button_found")
        asm:mov("edi", "ebx")
        asm:mov("eax", asm:m32("esi", CONTROL.title))
        asm:mov(asm:m32("ebp", -4), "eax")
        asm:mov("eax", asm:m32("esi", CONTROL.title_owner))
        asm:mov(asm:m32("ebp", -8), "eax")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.replacement_title))
        asm:mov(asm:m32("esi", CONTROL.title), "eax")
        asm:mov("eax", asm:m32("edi", ICON_RECORD.replacement_owner))
        asm:mov(asm:m32("esi", CONTROL.title_owner), "eax")
    
        asm:label("button_call_native")
        asm:push(asm:m32("ebp", 0x0C))
        asm:push(asm:m32("ebp", 0x08))
        asm:mov("ecx", "esi")
        asm:mov("eax", render_target)
        asm:call("eax")
        asm:mov(asm:m32("ebp", -0x0C), "eax")
        asm:test("edi", "edi")
        asm:je("button_done")
    
        asm:mov("eax", asm:m32("ebp", -4))
        asm:mov(asm:m32("esi", CONTROL.title), "eax")
        asm:mov("eax", asm:m32("ebp", -8))
        asm:mov(asm:m32("esi", CONTROL.title_owner), "eax")
    
        asm:mov("ecx", asm:m32("ebp", 0x08))
        asm:test("ecx", "ecx")
        asm:je("button_done")
        asm:cmp(asm:m32("ecx"), ADDRESS.gui_renderer_vtable)
        asm:jne("button_done")
        asm:mov("edx", asm:m32("edi", ICON_RECORD.texture))
        asm:test("edx", "edx")
        asm:je("button_done")
    
        asm:push(0)
        asm:push(asm:m32("edi", ICON_RECORD.source_height))
        asm:push(asm:m32("edi", ICON_RECORD.source_width))
        asm:push(0)
        asm:push(0)
        asm:push(asm:m32("edi", ICON_RECORD.color))
    
        asm:mov("eax", asm:m32("ebp", 0x0C))
        asm:mov("ebx", asm:m32("eax", 4))
        asm:add("ebx", asm:m32("esi", CONTROL.y))
        asm:mov("eax", asm:m32("esi", CONTROL.height))
        asm:sub("eax", asm:m32("edi", ICON_RECORD.destination_height))
        asm:sar("eax", 1)
        asm:add("ebx", "eax")
        asm:add("ebx", asm:m32("edi", ICON_RECORD.offset_y))
        asm:push("ebx")
    
        asm:mov("eax", asm:m32("ebp", 0x0C))
        asm:mov("ebx", asm:m32("eax"))
        asm:add("ebx", asm:m32("esi", CONTROL.x))
        asm:mov("eax", asm:m32("esi", CONTROL.width))
        asm:sar("eax", 1)
        asm:add("ebx", "eax")
        asm:add("ebx", asm:m32("edi", ICON_RECORD.anchor_x))
        asm:add("ebx", asm:m32("edi", ICON_RECORD.offset_x))
        asm:push("ebx")
    
        asm:mov("edx", asm:m32("edi", ICON_RECORD.texture))
        asm:movss("xmm0", asm:m32("edi", ICON_RECORD.scale))
        asm:mov("ecx", asm:m32("ebp", 0x08))
        asm:mov("eax", asm:m32("ecx"))
        asm:call(asm:m32("eax", 0x5C))
    
        asm:label("button_done")
        asm:mov("eax", asm:m32("ebp", -0x0C))
        asm:pop("edi")
        asm:pop("esi")
        asm:pop("ebx")
        asm:mov("esp", "ebp")
        asm:pop("ebp")
        asm:ret(8)
        return asm
    end
    
    local function emit(offset, assembler, maximum_size)
        local address = cave:at(offset)
        local code, size = assembler:finish(address)
        if maximum_size ~= nil and size > maximum_size then
            error("custom_tab: native bridge exceeds its reserved code-cave region", 2)
        end
        cave:write(offset, code, size, {flush = false})
        return address
    end
    
    local function initialise_native()
        if native ~= nil then
            return
        end
    
        cave = lifetime:alloc(CAVE.size, {fill = 0})
        local icon_registry_memory = lifetime:alloc(ffi.sizeof(IconRegistry), {fill = 0})
        local icon_registry_address = memory.address(icon_registry_memory.address)
    
        local bridge = {
            alloc = emit(CAVE.alloc, make_bridge(ADDRESS.allocator, 1)),
            tab_ctor = emit(CAVE.tab_ctor, make_bridge(ADDRESS.tab_ctor, 4)),
            string_ctor = emit(CAVE.string_ctor, make_bridge(ADDRESS.string_ctor, 2)),
            string_release = emit(CAVE.string_release, make_bridge(ADDRESS.string_release, 1)),
            category_ctor = emit(CAVE.category_ctor, make_bridge(ADDRESS.category_ctor, 6)),
            add_child = emit(CAVE.add_child, make_bridge(ADDRESS.add_child, 2)),
            layout = emit(CAVE.layout, make_bridge(ADDRESS.layout, 1)),
            full_layout = emit(
                CAVE.full_layout,
                make_bridge(ADDRESS.full_layout, 1)
            ),
            category_reflow = emit(
                CAVE.category_reflow,
                make_bridge(ADDRESS.category_reflow, 1)
            ),
            listbox_reflow = emit(
                CAVE.listbox_reflow,
                make_bridge(ADDRESS.listbox_reflow, 1)
            ),
            noop = emit(CAVE.noop, make_noop_bridge()),
            tab_reset = emit(CAVE.tab_reset, make_bridge(ADDRESS.tab_reset, 1)),
            tab_render = emit(
                CAVE.tab_render,
                make_tab_render_bridge(),
                0x1C0
            ),
            category_icon_render = emit(
                CAVE.category_icon_render,
                make_category_icon_render_bridge(
                    ADDRESS.category_render,
                    icon_registry_address
                ),
                0x400
            ),
            button_icon_render = emit(
                CAVE.button_icon_render,
                make_button_icon_render_bridge(
                    ADDRESS.button_render,
                    icon_registry_address
                ),
                0x200
            ),
            dpi_refresh = emit(
                CAVE.dpi_refresh,
                make_bridge(ADDRESS.dpi_refresh, 1)
            )
        }
    
        memory.flush(cave.address, CAVE.size)
        local thunk = memory.signature("engine.dll", "\xFF\xE1")
        local call1 = ffi.cast(
            "uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t)", thunk
        )
        local call2 = ffi.cast(
            "uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t)", thunk
        )
        local call4 = ffi.cast(
            "uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t)",
            thunk
        )
        local call6 = ffi.cast(
            "uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t)",
            thunk
        )
    
        native = {
            bridge = bridge,
            state = cave:ptr(ffi.typeof("$*", State), CAVE.state),
            icon_registry = icon_registry_memory:ptr(
                ffi.typeof("$*", IconRegistry),
                0
            ),
            icon_registry_memory = icon_registry_memory,
            tab_render_target = ADDRESS.tab_render,
            tab_slot_34_target = u32(ADDRESS.tab_vtable, 0x34)
        }
    
        function native.alloc(size)
            local address = tonumber(call1(bridge.alloc, 0, size))
            if address == nil or address == 0 then
                error("custom_tab: native GUI allocation failed", 2)
            end
            return address
        end
    
        function native.tab_ctor(object, menu, title, point)
            call4(bridge.tab_ctor, 0, object, menu, title, point)
        end
    
        function native.string_ctor(object, title)
            call2(bridge.string_ctor, 0, object, title)
        end
    
        function native.string_release(owner)
            call1(bridge.string_release, 0, owner)
        end
    
        function native.category_ctor(object, parent, title, grid)
            call6(bridge.category_ctor, 0, object, parent, title, grid, 0x0D, 1)
        end
    
        function native.add_child(parent, child)
            call2(bridge.add_child, 0, parent, child)
        end
    
        function native.layout(tab)
            call1(bridge.layout, 0, tab)
        end
    
        function native.full_layout(tab)
            call1(bridge.full_layout, 0, tab)
        end
    
        function native.reflow_category(category)
            call1(bridge.category_reflow, 0, category)
        end
    
        function native.reflow_listbox(listbox)
            call1(bridge.listbox_reflow, 0, listbox)
        end
    
        function native.reset_tab(tab)
            call1(bridge.tab_reset, 0, tab)
        end
    
        function native.refresh_dpi()
            call1(bridge.dpi_refresh, 0, 1)
        end
    
        native.tab_vtable = native.alloc(OBJECT_SIZE.tab_vtable)
        ffi.fill(ffi.cast("void*", native.tab_vtable), OBJECT_SIZE.tab_vtable, 0)
        ffi.copy(
            ffi.cast("void*", native.tab_vtable),
            ffi.cast("const void*", ADDRESS.tab_vtable),
            NATIVE_TAB_VTABLE_SIZES[ADDRESS.tab_vtable]
        )
        put_u32(native.tab_vtable, 0x10, bridge.tab_render)
        put_u32(native.tab_vtable, 0x34, bridge.noop)
        put_u32(native.tab_vtable, TAB_VTABLE_METADATA, CUSTOM_TAB_VTABLE_MAGIC)
        put_u32(native.tab_vtable, TAB_VTABLE_METADATA + 4, ADDRESS.tab_vtable)
    
        native.category_vtable = native.alloc(OBJECT_SIZE.category_vtable)
        ffi.copy(
            ffi.cast("void*", native.category_vtable),
            ffi.cast("const void*", ADDRESS.category_vtable),
            OBJECT_SIZE.category_vtable
        )
        put_u32(native.category_vtable, 0x10, bridge.category_icon_render)
    
        native.button_vtable = native.alloc(OBJECT_SIZE.button_vtable)
        ffi.copy(
            ffi.cast("void*", native.button_vtable),
            ffi.cast("const void*", ADDRESS.button_vtable),
            OBJECT_SIZE.button_vtable
        )
        put_u32(native.button_vtable, 0x10, bridge.button_icon_render)
    
    end
    
    local to_wide = memory.bind(
        "kernel32.dll",
        "MultiByteToWideChar",
        "int",
        {"uint32_t", "uint32_t", "const char*", "int", "uint16_t*", "int"}
    )
    
    local function utf8_title(value)
        if value == "" then
            return ffi.new("uint16_t[1]")
        end
        local length = to_wide(65001, 0, value, #value, nil, 0)
        if length <= 0 then
            error("custom_tab: invalid UTF-8 category name", 3)
        end
        local wide = ffi.new("uint16_t[?]", length + 1)
        to_wide(65001, 0, value, #value, wide, length)
        wide[length] = 0
        return wide
    end
    
    local function be32(data, offset)
        local a, b, c, d = data:byte(offset, offset + 3)
        return ((a * 256 + b) * 256 + c) * 256 + d
    end
    
    local function png_dimensions(data, source)
        if type(data) ~= "string" or #data < 24 then
            error("custom_tab: cannot read icon " .. source, 3)
        end
        if data:sub(1, 8) ~= PNG_SIGNATURE or data:sub(13, 16) ~= "IHDR" then
            error("custom_tab: icon is not a PNG: " .. source, 3)
        end
    
        local width = be32(data, 17)
        local height = be32(data, 21)
        if width < 1 or width > 4096 or height < 1 or height > 4096 then
            error("custom_tab: invalid PNG dimensions: " .. source, 3)
        end
        return width, height
    end
    
    local function load_texture_data(data, source)
        local width, height = png_dimensions(data, source)
    
        local texture = renderer.load_png(data, width, height)
        if texture == nil or texture == 0 then
            error("custom_tab: renderer.load_png failed for " .. source, 3)
        end
        return tonumber(texture), width, height
    end
    
    local load_library = memory.bind(
        "kernel32.dll",
        "LoadLibraryA",
        "uintptr_t",
        {"const char*"}
    )
    local global_alloc = memory.bind(
        "kernel32.dll",
        "GlobalAlloc",
        "void*",
        {"uint32_t", "uintptr_t"}
    )
    local global_lock = memory.bind(
        "kernel32.dll",
        "GlobalLock",
        "void*",
        {"void*"}
    )
    local global_unlock = memory.bind(
        "kernel32.dll",
        "GlobalUnlock",
        "int",
        {"void*"}
    )
    local global_free = memory.bind(
        "kernel32.dll",
        "GlobalFree",
        "void*",
        {"void*"}
    )
    
    local GdiplusStartupInput = ffi.typeof([[struct {
        uint32_t version;
        void* debug_callback;
        int suppress_background_thread;
        int suppress_external_codecs;
    }]])
    local GdipRect = ffi.typeof([[struct {
        int32_t x;
        int32_t y;
        int32_t width;
        int32_t height;
    }]])
    local GdipBitmapData = ffi.typeof([[struct {
        uint32_t width;
        uint32_t height;
        int32_t stride;
        int32_t pixel_format;
        void* scan0;
        uintptr_t reserved;
    }]])
    local GdiplusStartupInputBuffer = ffi.typeof("$[1]", GdiplusStartupInput)
    local GdipRectBuffer = ffi.typeof("$[1]", GdipRect)
    local GdipBitmapDataBuffer = ffi.typeof("$[1]", GdipBitmapData)
    
    local GDIP_PIXEL_FORMAT_32BPP_ARGB = 0x26200A
    local gdiplus_api
    local gdiplus_token
    
    local function gdip_status(status, operation)
        status = tonumber(status)
        if status ~= 0 then
            error(
                "custom_tab: GDI+ " .. operation .. " failed with status " .. status,
                3
            )
        end
    end
    
    local function initialise_gdiplus_bindings()
        if gdiplus_api ~= nil then
            return gdiplus_api
        end
        if tonumber(load_library("ole32.dll")) == 0 then
            error("custom_tab: cannot load ole32.dll", 3)
        end
        if tonumber(load_library("gdiplus.dll")) == 0 then
            error("custom_tab: cannot load gdiplus.dll", 3)
        end
    
        local thunk = memory.signature("engine.dll", "\xFF\xE1")
        gdiplus_api = {
            create_stream = memory.bind(
                "ole32.dll", "CreateStreamOnHGlobal", "int32_t",
                {"void*", "int", "void**"}
            ),
            startup = memory.bind(
                "gdiplus.dll", "GdiplusStartup", "int",
                {"uintptr_t*", "const void*", "void*"}
            ),
            shutdown = memory.bind(
                "gdiplus.dll", "GdiplusShutdown", "void", {"uintptr_t"}
            ),
            load_image_stream = memory.bind(
                "gdiplus.dll", "GdipLoadImageFromStream", "int",
                {"void*", "void**"}
            ),
            image_width = memory.bind(
                "gdiplus.dll", "GdipGetImageWidth", "int",
                {"void*", "uint32_t*"}
            ),
            image_height = memory.bind(
                "gdiplus.dll", "GdipGetImageHeight", "int",
                {"void*", "uint32_t*"}
            ),
            create_bitmap = memory.bind(
                "gdiplus.dll", "GdipCreateBitmapFromScan0", "int",
                {"int", "int", "int", "int", "void*", "void**"}
            ),
            image_graphics = memory.bind(
                "gdiplus.dll", "GdipGetImageGraphicsContext", "int",
                {"void*", "void**"}
            ),
            compositing_mode = memory.bind(
                "gdiplus.dll", "GdipSetCompositingMode", "int",
                {"void*", "int"}
            ),
            compositing_quality = memory.bind(
                "gdiplus.dll", "GdipSetCompositingQuality", "int",
                {"void*", "int"}
            ),
            interpolation_mode = memory.bind(
                "gdiplus.dll", "GdipSetInterpolationMode", "int",
                {"void*", "int"}
            ),
            pixel_offset_mode = memory.bind(
                "gdiplus.dll", "GdipSetPixelOffsetMode", "int",
                {"void*", "int"}
            ),
            smoothing_mode = memory.bind(
                "gdiplus.dll", "GdipSetSmoothingMode", "int",
                {"void*", "int"}
            ),
            create_attributes = memory.bind(
                "gdiplus.dll", "GdipCreateImageAttributes", "int", {"void**"}
            ),
            attributes_wrap = memory.bind(
                "gdiplus.dll", "GdipSetImageAttributesWrapMode", "int",
                {"void*", "int", "uint32_t", "int"}
            ),
            draw_image = memory.bind(
                "gdiplus.dll", "GdipDrawImageRectRectI", "int",
                {
                    "void*", "void*",
                    "int", "int", "int", "int",
                    "int", "int", "int", "int",
                    "int", "void*", "void*", "void*"
                }
            ),
            lock_bits = memory.bind(
                "gdiplus.dll", "GdipBitmapLockBits", "int",
                {"void*", "const void*", "uint32_t", "int", "void*"}
            ),
            unlock_bits = memory.bind(
                "gdiplus.dll", "GdipBitmapUnlockBits", "int",
                {"void*", "void*"}
            ),
            delete_graphics = memory.bind(
                "gdiplus.dll", "GdipDeleteGraphics", "int", {"void*"}
            ),
            dispose_image = memory.bind(
                "gdiplus.dll", "GdipDisposeImage", "int", {"void*"}
            ),
            dispose_attributes = memory.bind(
                "gdiplus.dll", "GdipDisposeImageAttributes", "int", {"void*"}
            ),
            release_stream = ffi.cast(
                "uintptr_t(__fastcall*)(uintptr_t, uintptr_t, void*)",
                thunk
            )
        }
        return gdiplus_api
    end
    
    local function ensure_gdiplus()
        local api = initialise_gdiplus_bindings()
        if gdiplus_token ~= nil then
            return api
        end
    
        local input = ffi.new(GdiplusStartupInputBuffer)
        input[0].version = 1
        local token = ffi.new("uintptr_t[1]")
        gdip_status(api.startup(token, input, nil), "startup")
        gdiplus_token = tonumber(token[0])
        if gdiplus_token == nil or gdiplus_token == 0 then
            error("custom_tab: GDI+ startup returned a null token", 3)
        end
        lifetime:defer(function()
            if gdiplus_token ~= nil then
                api.shutdown(gdiplus_token)
                gdiplus_token = nil
            end
            return true
        end)
        return api
    end
    
    local function release_stream(api, stream)
        if stream == nil then
            return
        end
        local vtable = ffi.cast("uintptr_t**", stream)[0]
        local release = tonumber(vtable[2])
        if release == 0 then
            error("custom_tab: invalid IStream vtable", 3)
        end
        api.release_stream(release, 0, stream)
    end
    
    local function high_quality_rgba(data, source, destination_width, destination_height)
        local source_width, source_height = png_dimensions(data, source)
        local api = ensure_gdiplus()
        local block = global_alloc(0x0002, #data)
        if memory.address(block) == 0 then
            error("custom_tab: GlobalAlloc failed for " .. source, 3)
        end
        local bytes = global_lock(block)
        if memory.address(bytes) == 0 then
            global_free(block)
            error("custom_tab: GlobalLock failed for " .. source, 3)
        end
        ffi.copy(bytes, data, #data)
        global_unlock(block)
    
        local stream_pointer = ffi.new("void*[1]")
        if tonumber(api.create_stream(block, 1, stream_pointer)) < 0 then
            global_free(block)
            error("custom_tab: CreateStreamOnHGlobal failed for " .. source, 3)
        end
    
        local stream = stream_pointer[0]
        if memory.address(stream) == 0 then
            global_free(block)
            error("custom_tab: CreateStreamOnHGlobal returned a null stream", 3)
        end
        local image
        local bitmap
        local graphics
        local attributes
        local bitmap_data
        local locked = false
        local ok, result = pcall(function()
            local output = ffi.new("void*[1]")
            gdip_status(api.load_image_stream(stream, output), "PNG decode")
            image = output[0]
            if memory.address(image) == 0 then
                error("custom_tab: GDI+ returned a null decoded image", 3)
            end
    
            local decoded_width = ffi.new("uint32_t[1]")
            local decoded_height = ffi.new("uint32_t[1]")
            gdip_status(api.image_width(image, decoded_width), "width query")
            gdip_status(api.image_height(image, decoded_height), "height query")
            if tonumber(decoded_width[0]) ~= source_width
                or tonumber(decoded_height[0]) ~= source_height
            then
                error("custom_tab: decoded PNG dimensions changed for " .. source, 3)
            end
    
            output[0] = nil
            gdip_status(
                api.create_bitmap(
                    destination_width,
                    destination_height,
                    0,
                    GDIP_PIXEL_FORMAT_32BPP_ARGB,
                    nil,
                    output
                ),
                "destination bitmap creation"
            )
            bitmap = output[0]
            if memory.address(bitmap) == 0 then
                error("custom_tab: GDI+ returned a null destination bitmap", 3)
            end
    
            output[0] = nil
            gdip_status(api.image_graphics(bitmap, output), "graphics creation")
            graphics = output[0]
            if memory.address(graphics) == 0 then
                error("custom_tab: GDI+ returned a null graphics context", 3)
            end
            gdip_status(api.compositing_mode(graphics, 1), "source-copy mode")
            gdip_status(api.compositing_quality(graphics, 2), "compositing quality")
            gdip_status(api.interpolation_mode(graphics, 7), "bicubic interpolation")
            gdip_status(api.pixel_offset_mode(graphics, 4), "half-pixel offset")
            gdip_status(api.smoothing_mode(graphics, 2), "smoothing quality")
    
            output[0] = nil
            gdip_status(api.create_attributes(output), "image attributes creation")
            attributes = output[0]
            if memory.address(attributes) == 0 then
                error("custom_tab: GDI+ returned null image attributes", 3)
            end
            gdip_status(api.attributes_wrap(attributes, 3, 0, 0), "edge wrap mode")
            gdip_status(
                api.draw_image(
                    graphics,
                    image,
                    0,
                    0,
                    destination_width,
                    destination_height,
                    0,
                    0,
                    source_width,
                    source_height,
                    2,
                    attributes,
                    nil,
                    nil
                ),
                "high-quality resize"
            )
    
            local rectangle = ffi.new(GdipRectBuffer)
            rectangle[0].x = 0
            rectangle[0].y = 0
            rectangle[0].width = destination_width
            rectangle[0].height = destination_height
            bitmap_data = ffi.new(GdipBitmapDataBuffer)
            gdip_status(
                api.lock_bits(
                    bitmap,
                    rectangle,
                    1,
                    GDIP_PIXEL_FORMAT_32BPP_ARGB,
                    bitmap_data
                ),
                "pixel lock"
            )
            locked = true
    
            local stride = tonumber(bitmap_data[0].stride)
            local row_bytes = math.abs(stride)
            if row_bytes < destination_width * 4 then
                error("custom_tab: invalid GDI+ bitmap stride", 3)
            end
            local scan0 = ffi.cast("uint8_t*", bitmap_data[0].scan0)
            local rgba = ffi.new(
                "uint8_t[?]",
                destination_width * destination_height * 4
            )
            for y = 0, destination_height - 1 do
                local source_y = stride < 0 and (destination_height - 1 - y) or y
                local input_row = scan0 + source_y * row_bytes
                local output_row = rgba + y * destination_width * 4
                for x = 0, destination_width - 1 do
                    local input_pixel = input_row + x * 4
                    local output_pixel = output_row + x * 4
                    output_pixel[0] = input_pixel[2]
                    output_pixel[1] = input_pixel[1]
                    output_pixel[2] = input_pixel[0]
                    output_pixel[3] = input_pixel[3]
                end
            end
            return ffi.string(rgba, destination_width * destination_height * 4)
        end)
    
        if locked then
            api.unlock_bits(bitmap, bitmap_data)
        end
        if attributes ~= nil and memory.address(attributes) ~= 0 then
            api.dispose_attributes(attributes)
        end
        if graphics ~= nil and memory.address(graphics) ~= 0 then
            api.delete_graphics(graphics)
        end
        if bitmap ~= nil and memory.address(bitmap) ~= 0 then
            api.dispose_image(bitmap)
        end
        if image ~= nil and memory.address(image) ~= 0 then
            api.dispose_image(image)
        end
        release_stream(api, stream)
        if not ok then
            error(result, 0)
        end
        return result
    end
    
    local function load_texture(path)
        return load_texture_data(readfile(path), path)
    end
    
    local function ensure_texture(object)
        if object.texture ~= nil then
            return
        end
        if object.icon_data ~= nil then
            object.texture,
            object.texture_source_width,
            object.texture_source_height = load_texture_data(object.icon_data, object.icon_path)
        else
            object.texture,
            object.texture_source_width,
            object.texture_source_height = load_texture(object.icon_path)
        end
        object.texture_path = object.icon_path
    end
    
    local function embedded_png_data(specification)
        if specification.png_data == nil then
            specification.png_data = specification.icon_data
                or readfile(specification.icon_path)
        end
        png_dimensions(specification.png_data, specification.icon_path)
        return specification.png_data
    end
    
    local function apply_icon(object)
        put_u32(object.address, TAB.icon, object.texture)
        put_u32(object.address, TAB.icon_u, 0)
        put_u32(object.address, TAB.icon_v, 0)
        put_u32(object.address, TAB.icon_width, object.texture_source_width)
        put_u32(object.address, TAB.icon_height, object.texture_source_height)
    end
    
    local function native_gui_dpi_scale()
        local scale = tonumber(ffi.cast("float*", ADDRESS.gui_dpi_scale)[0])
        if GUI_DPI_SCALES[scale] ~= true then
            error("custom_tab: invalid native GUI DPI multiplier", 3)
        end
        return scale
    end
    
    local function round_scaled(value, scale)
        local scaled = value * scale
        if scaled >= 0 then
            return floor(scaled + 0.5)
        end
        return ceil(scaled - 0.5)
    end
    
    local function fit_embedded_icon(specification, dpi_scale)
        local data = embedded_png_data(specification)
        local source_width, source_height = png_dimensions(
            data,
            specification.icon_path
        )
        local target_width = max(1, round_scaled(specification.box_width, dpi_scale))
        local target_height = max(1, round_scaled(specification.box_height, dpi_scale))
        local scale = min(
            target_width / source_width,
            target_height / source_height
        )
        local destination_width = max(1, floor(source_width * scale + 0.5))
        local destination_height = max(1, floor(source_height * scale + 0.5))
        local key = destination_width .. "x" .. destination_height
        local cached = specification.texture_cache[key]
        if cached == nil then
            local rgba = high_quality_rgba(
                data,
                specification.icon_path,
                destination_width,
                destination_height
            )
            local texture = renderer.load_rgba(
                rgba,
                destination_width,
                destination_height
            )
            if texture == nil or texture == 0 then
                error(
                    "custom_tab: renderer.load_rgba failed for "
                        .. specification.icon_path,
                    3
                )
            end
            cached = {
                texture = tonumber(texture),
                width = destination_width,
                height = destination_height
            }
            specification.texture_cache[key] = cached
        end
        specification.texture = cached.texture
        specification.texture_source_width = cached.width
        specification.texture_source_height = cached.height
        return 1.0, cached.width, cached.height
    end
    
    local function icon_record_address(field_offset, index)
        return native.icon_registry_memory:at(
            field_offset + index * ICON_RECORD.size
        )
    end
    
    local function clear_icon_registry()
        if native == nil or native.icon_registry == nil then
            return true
        end
    
        local registry = native.icon_registry[0]
        local category_count = tonumber(registry.category_count)
        local button_count = tonumber(registry.button_count)
        registry.category_count = 0
        registry.button_count = 0
    
        if handle ~= nil then
            for index = 1, #handle.categories_native do
                local address = handle.categories_native[index].address
                if u32(address, 0) == native.category_vtable then
                    put_u32(address, 0, ADDRESS.category_vtable)
                end
            end
            for address in pairs(handle.armed_button_vtables or {}) do
                if u32(address, 0) == native.button_vtable then
                    put_u32(address, 0, ADDRESS.button_vtable)
                end
            end
            handle.armed_button_vtables = {}
        end
    
        for index = 0, button_count - 1 do
            local owner = tonumber(registry.buttons[index].replacement_owner)
            if owner ~= 0 then
                native.string_release(owner)
            end
            ffi.fill(
                ffi.cast(
                    "void*",
                    icon_record_address(ICON_REGISTRY.buttons, index)
                ),
                ICON_RECORD.size,
                0
            )
        end
        for index = 0, category_count - 1 do
            local owner = tonumber(registry.categories[index].replacement_owner)
            if owner ~= 0 then
                native.string_release(owner)
            end
            ffi.fill(
                ffi.cast(
                    "void*",
                    icon_record_address(ICON_REGISTRY.categories, index)
                ),
                ICON_RECORD.size,
                0
            )
        end
        return true
    end
    
    local function write_icon_record(
        record,
        address,
        specification,
        anchor_x,
        dpi_scale
    )
        local scale, destination_width, destination_height = fit_embedded_icon(
            specification,
            dpi_scale
        )
        record.object = address
        record.texture = specification.texture
        record.source_width = specification.texture_source_width
        record.source_height = specification.texture_source_height
        record.scale = scale
        record.destination_width = destination_width
        record.destination_height = destination_height
        record.anchor_x = anchor_x or 0
        record.offset_x = round_scaled(specification.offset_x, dpi_scale)
        record.offset_y = round_scaled(specification.offset_y, dpi_scale)
        record.color = 0xFFFFFFFF
        record.flags = ICON_FLAG_IMAGE
        record.replacement_title = 0
        record.replacement_owner = 0
        return destination_width, destination_height
    end
    
    local function rebuild_icon_registry()
        if handle == nil or native == nil or handle.address == nil then
            return
        end
    
        clear_icon_registry()
        local registry = native.icon_registry[0]
        local dpi_scale = native_gui_dpi_scale()
        local category_count = 0
        for index = 1, #handle.category_names do
            local specification = handle.category_icons[index]
            local category = handle.categories_native[index]
            local hide_scrollbar = handle.category_hide_scrollbars[index] == true
            if category ~= nil and (specification ~= nil or hide_scrollbar) then
                if category_count >= MAX_CATEGORIES then
                    error("custom_tab: category icon registry is full", 2)
                end
                local record = registry.categories[category_count]
                record.object = category.address
                if specification ~= nil then
                    write_icon_record(
                        record,
                        category.address,
                        specification,
                        0,
                        dpi_scale
                    )
                    local empty_title = ffi.new("uint16_t[1]")
                    native.string_ctor(
                        icon_record_address(
                            ICON_REGISTRY.categories,
                            category_count
                        ) + ICON_RECORD.replacement_title,
                        memory.address(empty_title)
                    )
                end
                if hide_scrollbar then
                    record.flags = tonumber(record.flags) + ICON_FLAG_HIDE_SCROLLBAR
                    record.title_clip = math.max(18, round_scaled(18, dpi_scale))
                end
                if handle.category_noclip[index] == true then
                    record.flags = tonumber(record.flags) + ICON_FLAG_NO_CLIP
                end
                category_count = category_count + 1
                registry.category_count = category_count
                put_u32(category.address, 0, native.category_vtable)
            end
        end
    
        local button_count = 0
        for index = 1, #handle.button_icons do
            local configured = handle.button_icons[index]
            if configured.mount.active then
                if button_count >= MAX_BUTTON_ICONS then
                    error("custom_tab: button icon registry is full", 2)
                end
                local record = registry.buttons[button_count]
                local destination_width = write_icon_record(
                    record,
                    configured.address,
                    configured.specification,
                    0,
                    dpi_scale
                )
                record.anchor_x = -floor(destination_width / 2)
                local empty_title = ffi.new("uint16_t[1]")
                native.string_ctor(
                    icon_record_address(
                        ICON_REGISTRY.buttons,
                        button_count
                    ) + ICON_RECORD.replacement_title,
                    memory.address(empty_title)
                )
                button_count = button_count + 1
                registry.button_count = button_count
                put_u32(configured.address, 0, native.button_vtable)
                handle.armed_button_vtables[configured.address] = true
            end
        end
        handle.icon_registry_dpi_scale = dpi_scale
        handle.icon_registry_dirty = false
    end
    
    local function tab_vector(menu)
        local begin = u32(menu, MENU.tabs_begin)
        local finish = u32(menu, MENU.tabs_end)
        local capacity = u32(menu, MENU.tabs_capacity)
        local count = (finish - begin) / 4
        local pointers = ffi.cast("uint32_t*", begin)
        local tabs = {}
    
        for index = 0, count - 1 do
            local address = tonumber(pointers[index])
            tabs[index + 1] = {
                address = address,
                index = u32(address, TAB.index),
                x = u32(address, TAB.x),
                y = u32(address, TAB.y),
                width = u32(address, TAB.width),
                height = u32(address, TAB.height),
                visible = u8(address, TAB.visible),
                hover = u8(address, TAB.hover),
                icon = u32(address, TAB.icon)
            }
        end
    
        return {
            begin = begin,
            finish = finish,
            capacity = capacity,
            count = count,
            active = u32(menu, MENU.active),
            tabs = tabs
        }
    end
    
    local function remember_menu_size()
        if handle == nil or not handle.installed then
            return
        end
        handle.width = u32(handle.menu, MENU.width)
        handle.height = u32(handle.menu, MENU.height)
    end
    
    local function relayout_native_tabs(menu)
        local vector = tab_vector(menu)
        for index = 1, vector.count do
            native.full_layout(vector.tabs[index].address)
        end
        return vector.count
    end

    local function apply_menu_size(menu, width, height)
        put_u32(menu, MENU.width, width)
        put_u32(menu, MENU.height, height)
        relayout_native_tabs(menu)
    end
    
    local function insertion_slot(vector, position)
        if position == "after_lua" then
            return vector.count
        end
        return min(position, vector.count)
    end
    
    local function category_grid(index, count)
        local columns = min(6, max(1, ceil(count / 12)))
        local rows = ceil(count / columns)
        local cell_width = max(3, floor(24 / columns))
        local cell_height = max(2, floor(24 / rows))
        local column = (index - 1) % columns
        local row = floor((index - 1) / columns)
        local x = column * cell_width
        local y = row * cell_height
        local width = column == columns - 1 and 24 - x or cell_width
        local height = row == rows - 1 and 24 - y or cell_height
        return x + width * 0x100 + y * 0x10000 + height * 0x1000000
    end
    
    local function create_category(index)
        local name = handle.category_names[index]
        local wide = utf8_title(name)
        local address = native.alloc(OBJECT_SIZE.category)
        native.category_ctor(
            address,
            handle.address,
            memory.address(wide),
            handle.category_layouts[index]
                or category_grid(index, #handle.category_names)
        )
        if handle.category_layout_locks[index] == true then
            put_u8(address, CATEGORY.layout_editable, 0)
            put_u32(address, CATEGORY.layout_mode, 0)
        end
        native.add_child(handle.address, address)
        return {address = address, name = name}
    end
    
    local function relayout_categories()
        local count = #handle.categories_native
        if count == 0 then
            return
        end
        for index = 1, count do
            if handle.category_layouts[index] == nil then
                handle.category_layouts[index] = category_grid(index, count)
            end
            put_u32(
                handle.categories_native[index].address,
                CATEGORY.grid,
                handle.category_layouts[index]
            )
            if handle.category_layout_locks[index] == true then
                put_u8(
                    handle.categories_native[index].address,
                    CATEGORY.layout_editable,
                    0
                )
                put_u32(
                    handle.categories_native[index].address,
                    CATEGORY.layout_mode,
                    0
                )
            end
        end
        native.full_layout(handle.address)
    end
    
    local function remember_category_layouts()
        if handle == nil or not handle.installed then
            return
        end
        for index = 1, #handle.categories_native do
            handle.category_layouts[index] = u32(
                handle.categories_native[index].address,
                CATEGORY.grid
            )
        end
    end
    
    local function reserve_controls(category, additional)
        local begin = u32(category, CATEGORY.controls_begin)
        local finish = u32(category, CATEGORY.controls_end)
        local capacity = u32(category, CATEGORY.controls_capacity)
        local count = (finish - begin) / 4
        if finish + additional * 4 <= capacity then
            return begin, finish, count
        end
    
        local slots = max(count + additional, max(8, count * 2))
        local replacement = native.alloc(slots * 4)
        if count > 0 then
            ffi.copy(
                ffi.cast("void*", replacement),
                ffi.cast("const void*", begin),
                count * 4
            )
        end
        begin = replacement
        finish = replacement + count * 4
        put_u32(category, CATEGORY.controls_begin, begin)
        put_u32(category, CATEGORY.controls_end, finish)
        put_u32(category, CATEGORY.controls_capacity, replacement + slots * 4)
        return begin, finish, count
    end
    
    local function append_controls(category, controls_to_append)
        local _, finish = reserve_controls(category, #controls_to_append)
        local output = ffi.cast("uint32_t*", finish)
        for index = 1, #controls_to_append do
            output[index - 1] = controls_to_append[index]
        end
        put_u32(
            category,
            CATEGORY.controls_end,
            finish + #controls_to_append * 4
        )
    end
    
    local function remove_controls(category, controls_to_remove)
        local removed = {}
        for index = 1, #controls_to_remove do
            removed[controls_to_remove[index]] = true
        end
    
        local begin = u32(category, CATEGORY.controls_begin)
        local finish = u32(category, CATEGORY.controls_end)
        local pointers = ffi.cast("uint32_t*", begin)
        local count = (finish - begin) / 4
        local output = 0
        for index = 0, count - 1 do
            local control = tonumber(pointers[index])
            if not removed[control] then
                pointers[output] = control
                output = output + 1
            end
        end
        put_u32(category, CATEGORY.controls_end, begin + output * 4)
    end
    
    local function lua_tab_address(vector)
        for index = 1, vector.count do
            if vector.tabs[index].icon == 0xFFFFFFFF then
                return vector.tabs[index].address
            end
        end
    end
    
    local function lua_categories(vector)
        local lua_tab = lua_tab_address(vector)
        if lua_tab == nil then
            return nil
        end
    
        local begin = u32(lua_tab, TAB.children_begin)
        local finish = u32(lua_tab, TAB.children_end)
        local pointers = ffi.cast("uint32_t*", begin)
        local result = {}
        for index = 0, (finish - begin) / 4 - 1 do
            result[index + 1] = tonumber(pointers[index])
        end
        return result
    end
    
    local function available_tab_vector()
        local menu = u32(ADDRESS.menu, 0)
        if menu == 0 then
            return nil
        end
        return tab_vector(menu)
    end
    
    local function capture_mount_controls(mount, vector)
        if mount.controls ~= nil then
            return true
        end
    
        vector = vector or available_tab_vector()
        if vector == nil then
            return false
        end
    
        local sources = lua_categories(vector)
        local source = sources ~= nil and sources[mount.source_index] or nil
        if source == nil then
            return false
        end
    
        local begin = u32(source, CATEGORY.controls_begin)
        local finish = u32(source, CATEGORY.controls_end)
        local first = finish - mount.count * 4
        if first < begin then
            error("custom_tab: adopted control count exceeds the LUA category", 3)
        end
    
        local pointers = ffi.cast("uint32_t*", first)
        local controls = {}
        for index = 0, mount.count - 1 do
            controls[index + 1] = tonumber(pointers[index])
        end
    
        mount.source = source
        mount.controls = controls
        remove_controls(source, controls)
        return true
    end
    
    local function listbox_item_count(address)
        local begin = u32(address, CONTROL.listbox_items_begin)
        local finish = u32(address, CONTROL.listbox_items_end)
        local bytes = finish - begin
        if bytes < 0 or bytes % LISTBOX_ITEM_INDEX_SIZE ~= 0 then
            error("custom_tab: invalid native listbox item vector", 3)
        end
        return bytes / LISTBOX_ITEM_INDEX_SIZE
    end
    
    local function refresh_listbox(record)
        if not record.active or not record.fit_items then
            return false
        end
    
        local row_height = u32(record.address, CONTROL.listbox_row_height)
        if row_height < 1 then
            error("custom_tab: native listbox row height is invalid", 3)
        end
        local header_rows = u8(record.address, CONTROL.listbox_header) ~= 0 and 1 or 0
        local height = row_height * (listbox_item_count(record.address) + header_rows)
            + record.fit_padding
        if u32(record.address, CONTROL.height) == height
            and u32(record.address, CONTROL.intrinsic_height) == height
        then
            return false
        end
    
        put_u32(record.address, CONTROL.height, height)
        put_u32(record.address, CONTROL.intrinsic_height, height)
        native.reflow_listbox(record.address)
        return true
    end
    
    local function set_listbox_header(record, value)
        if record.hide_header then
            put_u8(record.address, CONTROL.listbox_header, value)
        end
    end
    
    local function activate_listbox(record, parent)
        record.parent = parent
        record.active = true
        set_listbox_header(record, 0)
        return refresh_listbox(record)
    end
    
    local function deactivate_listbox(record, reflow)
        if not record.active then
            return
        end
        set_listbox_header(record, record.original_header)
        if record.fit_items then
            put_u32(record.address, CONTROL.height, record.original_height)
            put_u32(
                record.address,
                CONTROL.intrinsic_height,
                record.original_intrinsic_height
            )
            if reflow ~= false then
                native.reflow_listbox(record.address)
            end
        end
        record.parent = nil
        record.active = false
    end
    
    local function activate_mount_listboxes(mount)
        local changed = false
        for index = 1, #handle.listboxes do
            local record = handle.listboxes[index]
            if record.mount == mount and activate_listbox(record, mount.target) then
                changed = true
            end
        end
        if changed then
            native.reflow_category(mount.target)
        end
    end
    
    local function deactivate_mount_listboxes(mount, reflow)
        for index = 1, #handle.listboxes do
            local record = handle.listboxes[index]
            if record.mount == mount then
                deactivate_listbox(record, reflow)
            end
        end
    end
    
    local function refresh_listboxes()
        local changed_parents = {}
        for index = 1, #handle.listboxes do
            local record = handle.listboxes[index]
            if refresh_listbox(record) then
                changed_parents[record.parent] = true
            end
        end
        for parent in pairs(changed_parents) do
            native.reflow_category(parent)
        end
    end
    
    local function apply_mount(mount, vector)
        if mount.active then
            return
        end
    
        local sources = lua_categories(vector)
        local source = sources ~= nil and sources[mount.source_index] or nil
        if source == nil or not capture_mount_controls(mount, vector) then
            return
        end
    
        local category = handle.categories_native[mount.target_index]
        if category == nil then
            error(
                "custom_tab: native target category is unavailable during mount",
                3
            )
        end
        local target = category.address
        local mounted = mount.controls
        mount.source_scroll_state = {
            value_90 = u32(source, 0x90),
            visible = u8(source, 0x94),
            value_98 = u32(source, 0x98),
            value_9c = u32(source, 0x9C),
            value_a0 = u32(source, 0xA0),
            offset = u32(source, 0xA8)
        }
        mount.control_geometry = {}
        for index = 1, #mounted do
            local control = mounted[index]
            local geometry = ffi.new("uint8_t[?]", 0x18)
            ffi.copy(
                geometry,
                ffi.cast("const void*", control + CONTROL.x),
                0x18
            )
            mount.control_geometry[index] = {
                parent = u32(control, CONTROL.parent),
                bytes = geometry
            }
            put_u32(control, CATEGORY.parent, target)
        end
    
        remove_controls(source, mounted)
        native.reflow_category(source)
        append_controls(target, mounted)
        mount.source = source
        mount.target = target
        mount.controls = mounted
        mount.active = true
        activate_mount_listboxes(mount)
    end
    
    local function apply_mounts(vector)
        for index = 1, #handle.mounts do
            apply_mount(handle.mounts[index], vector)
        end
    end
    
    local function restore_mounts()
        -- Controls are detached from the native LUA category in the same order
        -- that their groups are created. Restore mounts in that exact order:
        -- append_controls() appends to the source vector, so walking backwards
        -- reverses the original group order on every Lua reload and can make
        -- Skeet reflow the group boxes into progressively narrower columns.
        for index = 1, #handle.mounts do
            local mount = handle.mounts[index]
            if mount.active then
                deactivate_mount_listboxes(mount, false)
                remove_controls(mount.target, mount.controls)
                for control_index = 1, #mount.controls do
                    local control = mount.controls[control_index]
                    local geometry = mount.control_geometry[control_index]
                    put_u32(control, CATEGORY.parent, geometry.parent)
                    ffi.copy(
                        ffi.cast("void*", control + CONTROL.x),
                        geometry.bytes,
                        0x18
                    )
                end
                append_controls(mount.source, mount.controls)
                local scroll = mount.source_scroll_state
                put_u32(mount.source, 0x90, scroll.value_90)
                put_u8(mount.source, 0x94, scroll.visible)
                put_u32(mount.source, 0x98, scroll.value_98)
                put_u32(mount.source, 0x9C, scroll.value_9c)
                put_u32(mount.source, 0xA0, scroll.value_a0)
                put_u32(mount.source, 0xA8, scroll.offset)
                mount.source = nil
                mount.target = nil
                mount.source_scroll_state = nil
                mount.control_geometry = nil
                mount.active = false
            end
        end
    end
    
    local function is_clipped_tab_vtable(address)
        return NATIVE_TAB_VTABLE_SIZES[address] ~= nil
            or u32(address, TAB_VTABLE_METADATA) == CLIPPED_TAB_VTABLE_MAGIC
    end
    
    local function collapse_neutral_clipped_tab_vtables(address)
        local depth = 0
        while NATIVE_TAB_VTABLE_SIZES[address] == nil
            and u32(address, TAB_VTABLE_METADATA) == CLIPPED_TAB_VTABLE_MAGIC
            and u32(address, 0x10) == ADDRESS.tab_render
        do
            local previous = u32(address, TAB_VTABLE_METADATA + 4)
            if previous == 0 or previous == address then
                error("custom_tab: invalid clipped native tab vtable chain", 2)
            end
            address = previous
            depth = depth + 1
            if depth > 32 then
                error("custom_tab: clipped native tab vtable chain is too deep", 2)
            end
        end
        return address
    end
    
    local function arm_clipped_native_tabs(vector, slot)
        handle.clipped_tab_vtables = {}
        for index = 1, vector.count do
            local tab = vector.tabs[index]
            local old_position = index - 1
            if old_position >= slot and tab.icon ~= 0xFFFFFFFF then
                local original_vtable = u32(tab.address, 0)
                if is_clipped_tab_vtable(original_vtable) then
                    local clone = native.alloc(CLIPPED_TAB_VTABLE_SIZE)
                    ffi.fill(ffi.cast("void*", clone), CLIPPED_TAB_VTABLE_SIZE, 0)
                    local copy_size = NATIVE_TAB_VTABLE_SIZES[original_vtable]
                        or TAB_VTABLE_SLOT_REGION
                    ffi.copy(
                        ffi.cast("void*", clone),
                        ffi.cast("const void*", original_vtable),
                        copy_size
                    )
                    put_u32(clone, 0x10, native.bridge.tab_render)
                    put_u32(clone, TAB_VTABLE_METADATA, CLIPPED_TAB_VTABLE_MAGIC)
                    put_u32(clone, TAB_VTABLE_METADATA + 4, original_vtable)
                    handle.clipped_tab_vtables[#handle.clipped_tab_vtables + 1] = {
                        object = tab.address,
                        original = original_vtable,
                        clone = clone
                    }
                    put_u32(tab.address, 0, clone)
                end
            end
        end
    end
    
    local function restore_clipped_native_tabs()
        for index = #handle.clipped_tab_vtables, 1, -1 do
            local record = handle.clipped_tab_vtables[index]
            if u32(record.object, 0) == record.clone then
                put_u32(
                    record.object,
                    0,
                    collapse_neutral_clipped_tab_vtables(record.original)
                )
            end
            put_u32(record.clone, 0x10, ADDRESS.tab_render)
        end
        handle.clipped_tab_vtables = {}
        return true
    end
    
    local function grow_tab_vector(menu, vector)
        if vector.finish + 4 <= vector.capacity then
            return
        end
    
        local bytes = (vector.count + 1) * 4
        local replacement = native.alloc(bytes)
        ffi.copy(
            ffi.cast("void*", replacement),
            ffi.cast("const void*", vector.begin),
            vector.count * 4
        )
    
        vector.begin = replacement
        vector.finish = replacement + vector.count * 4
        vector.capacity = replacement + bytes
        put_u32(menu, MENU.tabs_begin, vector.begin)
        put_u32(menu, MENU.tabs_capacity, vector.capacity)
    end
    
    local function arm_native_vtable()
        put_u32(native.tab_vtable, 0x10, native.bridge.tab_render)
        put_u32(native.tab_vtable, 0x34, native.bridge.noop)
        put_u32(native.category_vtable, 0x10, native.bridge.category_icon_render)
        put_u32(native.button_vtable, 0x10, native.bridge.button_icon_render)
    end
    
    local function neutralise_native_vtable()
        if native == nil or native.tab_vtable == nil then
            return true
        end
        if handle ~= nil
            and handle.address ~= nil
            and u32(handle.address, 0) == native.tab_vtable
        then
            put_u32(handle.address, 0, ADDRESS.tab_vtable)
        end
        put_u32(native.tab_vtable, 0x10, native.tab_render_target)
        put_u32(native.tab_vtable, 0x34, native.tab_slot_34_target)
        put_u32(native.category_vtable, 0x10, ADDRESS.category_render)
        put_u32(native.button_vtable, 0x10, ADDRESS.button_render)
        native.state[0].custom_tab = 0
        return true
    end
    
    local function cleanup_attempt(errors, label, operation)
        local ok, result, detail = pcall(operation)
        if not ok then
            errors[#errors + 1] = label .. ": " .. tostring(result)
            return false
        end
        if result == false then
            errors[#errors + 1] = label .. ": "
                .. tostring(detail or "operation returned false")
            return false
        end
        return true
    end
    
    local function install_handle()
        if handle == nil or handle.destroyed or handle.installed then
            return
        end
    
        initialise_native()
    
        local menu = u32(ADDRESS.menu, 0)
        if menu == 0 then
            return
        end
    
        ensure_texture(handle)
        handle.installing = true
        handle.menu = menu
        handle.install_original_width = u32(menu, MENU.width)
        handle.install_original_height = u32(menu, MENU.height)
        if handle.width ~= nil then
            apply_menu_size(menu, handle.width, handle.height)
        end
        local vector = tab_vector(menu)
        if vector.count < 1 then
            error("custom_tab: native tab vector is empty", 2)
        end
        local slot = insertion_slot(vector, handle.position)
        local anchor = slot < vector.count
            and vector.tabs[slot + 1]
            or vector.tabs[vector.count]
        local x = anchor.x
        local y = slot < vector.count and anchor.y or anchor.y + anchor.height
        local point = ffi.new("int32_t[2]", {x, y})
        local empty_title = ffi.new("uint16_t[1]")
        local address = native.alloc(OBJECT_SIZE.tab)
    
        handle.address = address
        handle.menu = menu
        handle.saved = vector
        handle.slot = slot
        handle.inserted = false
        handle.categories_native = {}
    
        native.tab_ctor(
            address,
            menu,
            memory.address(empty_title),
            memory.address(point)
        )
        native.state[0].custom_tab = address
        native.state[0].icon_offset_x = handle.icon_offset_x
        native.state[0].icon_offset_y = handle.icon_offset_y
        arm_native_vtable()
        put_u32(address, 0, native.tab_vtable)
        put_u32(address, TAB.index, slot)
        apply_icon({
            address = address,
            texture = handle.texture,
            texture_source_width = handle.texture_source_width,
            texture_source_height = handle.texture_source_height
        })
    
        for index = 1, #handle.category_names do
            handle.categories_native[index] = create_category(index)
        end
        apply_mounts(vector)
        relayout_categories()
    
        grow_tab_vector(menu, vector)
        local pointers = ffi.cast("uint32_t*", vector.begin)
        for index = vector.count, slot + 1, -1 do
            pointers[index] = pointers[index - 1]
        end
        pointers[slot] = address
        put_u32(menu, MENU.tabs_end, vector.finish + 4)
        handle.inserted = true
    
        for index = 1, vector.count do
            local saved = vector.tabs[index]
            local old_position = index - 1
            if old_position >= slot then
                put_u32(saved.address, TAB.index, old_position + 1)
                put_u32(saved.address, TAB.y, saved.y + anchor.height)
            else
                put_u32(saved.address, TAB.index, old_position)
            end
        end
        arm_clipped_native_tabs(vector, slot)
    
        local active = vector.active >= slot and vector.active + 1 or vector.active
        put_u32(menu, MENU.active, active)
        handle.installed = true
        native.refresh_dpi()
        relayout_categories()
        refresh_listboxes()
        rebuild_icon_registry()
        handle.installing = false
        -- Restore the exact dimensions and relayout every native tab.
        -- Restoring the fields directly leaves the original Skeet tabs with
        -- geometry calculated for the temporary menu size used during install.
        if handle.install_original_width ~= nil
            and handle.install_original_height ~= nil
        then
            apply_menu_size(
                menu,
                handle.install_original_width,
                handle.install_original_height
            )
        end
        handle.install_original_width = nil
        handle.install_original_height = nil
    end
    
    local function restore_tab_vector(owner)
        if owner.menu == nil or not owner.inserted then
            return true
        end
    
        local menu = owner.menu
        local begin = u32(menu, MENU.tabs_begin)
        local finish = u32(menu, MENU.tabs_end)
        local bytes = finish - begin
        if bytes < 0 or bytes % 4 ~= 0 then
            error("custom_tab: invalid native tab vector during cleanup", 2)
        end
        local count = bytes / 4
        local pointers = ffi.cast("uint32_t*", begin)
    
        local slot
        for index = 0, count - 1 do
            if tonumber(pointers[index]) == owner.address then
                slot = index
                break
            end
        end
        if slot == nil then
            error("custom_tab: installed tab is missing from the native vector", 2)
        end
    
        local row_height = u32(owner.address, TAB.height)
        if row_height < 1 then
            error("custom_tab: installed tab has an invalid row height", 2)
        end
        for index = slot, count - 2 do
            pointers[index] = pointers[index + 1]
        end
        pointers[count - 1] = 0
        put_u32(menu, MENU.tabs_end, finish - 4)
    
        local remaining = count - 1
        for index = slot, remaining - 1 do
            local address = tonumber(pointers[index])
            put_u32(address, TAB.index, index)
            put_u32(address, TAB.y, u32(address, TAB.y) - row_height)
        end
    
        local active = u32(menu, MENU.active)
        if active == slot then
            active = min(slot, remaining - 1)
        elseif active > slot then
            active = active - 1
        end
        put_u32(menu, MENU.active, active)
        owner.inserted = false
        return true
    end
    
    local function restore_handle()
        local owner = handle
        if owner == nil then
            return true
        end
        if owner.address == nil and not owner.installed and not owner.installing then
            return true
        end
    
        local errors = {}
        local preserved_menu_width, preserved_menu_height
        if owner.installed and owner.menu ~= nil then
            local size_ok, current_width, current_height = pcall(function()
                return u32(owner.menu, MENU.width), u32(owner.menu, MENU.height)
            end)
            if size_ok and current_width > 0 and current_height > 0 then
                preserved_menu_width = current_width
                preserved_menu_height = current_height
            end
            cleanup_attempt(errors, "remember menu size", remember_menu_size)
            cleanup_attempt(
                errors,
                "remember category layouts",
                remember_category_layouts
            )
        end
        if owner.address ~= nil and native ~= nil then
            cleanup_attempt(errors, "reset native tab state", function()
                native.reset_tab(owner.address)
                return true
            end)
            cleanup_attempt(errors, "hide native tab object", function()
                put_u8(owner.address, TAB.visible, 0)
                put_u8(owner.address, TAB.hover, 0)
                return true
            end)
        end
    
        local vector_restored = cleanup_attempt(errors, "restore native tab vector", function()
            return restore_tab_vector(owner)
        end)
        if vector_restored then
            cleanup_attempt(errors, "refresh native DPI layout", function()
                native.refresh_dpi()
                return true
            end)
            cleanup_attempt(errors, "relayout restored native tabs", function()
                if owner.menu == nil then
                    error("custom_tab: menu is unavailable during native relayout", 2)
                end
                relayout_native_tabs(owner.menu)
                return true
            end)
            cleanup_attempt(
                errors,
                "restore clipped native tab vtables",
                restore_clipped_native_tabs
            )
        end
        cleanup_attempt(errors, "clear embedded icon registry", clear_icon_registry)
        if native ~= nil then
            local mounts_restored = cleanup_attempt(
                errors,
                "restore mounted controls",
                restore_mounts
            )
            if vector_restored and mounts_restored then
                cleanup_attempt(errors, "final relayout of restored native tabs", function()
                    if owner.menu == nil then
                        error("custom_tab: menu is unavailable during final native relayout", 2)
                    end
                    relayout_native_tabs(owner.menu)
                    return true
                end)
            end
            if vector_restored
                and mounts_restored
                and owner.installed
                and #owner.mounts > 0
            then
                cleanup_attempt(errors, "relayout restored LUA controls", function()
                    local vector = tab_vector(owner.menu)
                    local lua_tab = lua_tab_address(vector)
                    if lua_tab == nil then
                        error("custom_tab: LUA tab is unavailable during cleanup", 2)
                    end
                    native.full_layout(lua_tab)
                    return true
                end)
            end
            if vector_restored then
                cleanup_attempt(
                    errors,
                    "neutralise object-local render vtables",
                    neutralise_native_vtable
                )
            end
        end
    
        cleanup_attempt(errors, "neutralise native categories", function()
            for index = 1, #owner.categories_native do
                put_u32(
                    owner.categories_native[index].address,
                    0,
                    ADDRESS.category_vtable
                )
            end
            return true
        end)
    
        if preserved_menu_width ~= nil and owner.menu ~= nil then
            cleanup_attempt(errors, "preserve menu size on unload", function()
                put_u32(owner.menu, MENU.width, preserved_menu_width)
                put_u32(owner.menu, MENU.height, preserved_menu_height)
                return true
            end)
        end
    
        owner.installed = false
        owner.installing = false
        if #errors ~= 0 then
            return false, table.concat(errors, "; ")
        end
    
        owner.address = nil
        owner.menu = nil
        owner.saved = nil
        owner.slot = nil
        owner.inserted = false
        owner.install_original_width = nil
        owner.install_original_height = nil
        owner.categories_native = {}
        return true
    end
    
    local Handle = {}
    Handle.__index = Handle

    -- Reflow an adopted category after changing native SameLine flags.
    -- The next paint_ui pass can then apply the centered positions on top.
    function Handle:reflow_category(index)
        local category = self.categories_native and self.categories_native[index]
        if native == nil or category == nil or category.address == nil then
            return false
        end
        local ok = pcall(native.reflow_category, category.address)
        return ok
    end
    
    local function mounted_control_for_reference(reference)
        for mount_index = 1, #handle.mounts do
            local mount = handle.mounts[mount_index]
            if mount.references ~= nil then
                for control_index = 1, #mount.references do
                    if mount.references[control_index] == reference then
                        return mount, mount.controls[control_index]
                    end
                end
            end
        end
    end
    
    local function validate_mount_source(source_index, level)
        if source_index ~= 1 and source_index ~= 2 then
            error(
                "custom_tab: source category must be 1 (LUA/A) or 2 (LUA/B)",
                level or 3
            )
        end
    end
    
    local function validate_mount_target(self, target_index, level)
        if not is_integer(target_index)
            or target_index < 1
            or target_index > #self.category_names
        then
            error(
                "custom_tab: target category index is out of range",
                level or 3
            )
        end
    end
    
    local function copy_references(references)
        if references == nil then
            return nil
        end
        local result = {}
        for index = 1, #references do
            result[index] = references[index]
        end
        return result
    end
    
    local function tail_controls(first, count)
        local pointers = ffi.cast("uint32_t*", first)
        local controls = {}
        for index = 0, count - 1 do
            controls[index + 1] = tonumber(pointers[index])
        end
        return controls
    end
    
    local function control_position_in_menu(self, address)
        local x = u32(address, CONTROL.x)
        local y = u32(address, CONTROL.y)
        local parent = u32(address, CONTROL.parent)
        while parent ~= 0 and parent ~= self.address and parent ~= self.menu do
            x = x + u32(parent, CONTROL.x)
            y = y + u32(parent, CONTROL.y)
            parent = u32(parent, CONTROL.parent)
        end
        return u32(self.menu, MENU.x) + x, u32(self.menu, MENU.y) + y
    end
    
    function Handle:add_category(name)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        if #self.category_names >= MAX_CATEGORIES then
            error("custom_tab: category limit reached", 2)
        end
    
        local definition = type(name) == "table" and name or nil
        if definition ~= nil then
            name = definition.name
        end
        name = check_name(name, 2)
        self.category_names[#self.category_names + 1] = name
        local added_index = #self.category_names
        self.category_icons[added_index] = category_icon_from_definition(
            definition,
            2
        )
        for index = 1, #self.category_names do
            self.category_layouts[index] = category_grid(
                index,
                #self.category_names
            )
        end
        if self.installed then
            local index = #self.category_names
            self.categories_native[index] = create_category(index)
            relayout_categories()
            if self.category_icons[index] ~= nil then
                self.icon_registry_dirty = true
            end
            return self.categories_native[index]
        end
    end
    
    function Handle:set_category_name(index, name)
        if not is_integer(index) or index < 1 or index > #self.category_names then
            error("custom_tab: category index is out of range", 2)
        end
    
        name = check_name(name, 2)
        -- Keep the native category title intact between page changes. Rebuilding
        -- the same string on every paint_ui update can restart Skeet's transition.
        if self.category_names[index] == name then
            return self
        end

        local category = self.categories_native[index]
        if category ~= nil then
            local wide = utf8_title(name)
            native.string_release(u32(category.address, CATEGORY.title_owner))
            native.string_ctor(
                category.address + CATEGORY.title,
                memory.address(wide)
            )
            category.name = name
        end
        self.category_names[index] = name
        return self
    end

    function Handle:set_category_visible(index, visible)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        if not is_integer(index) or index < 1 or index > #self.category_names then
            error("custom_tab: category index is out of range", 2)
        end

        local category = self.categories_native[index]
        if category == nil or category.address == nil then
            return false
        end
        local desired_visibility = visible and 1 or 0
        -- Only notify the native menu when visibility actually changes, so its
        -- built-in show/hide transition is not reset every frame.
        if u8(category.address, CATEGORY.visible) == desired_visibility then
            return self
        end
        put_u8(category.address, CATEGORY.visible, desired_visibility)
        return self
    end
    
    function Handle:set_control_name(reference, name)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        if type(name) ~= "string" then
            error("custom_tab: control name must be a string", 2)
        end
        local mount, address = mounted_control_for_reference(reference)
        if mount == nil or address == nil then
            error("custom_tab: control is not mounted", 2)
        end
        local wide = utf8_title(name)
        native.string_release(u32(address, CONTROL.title_owner))
        native.string_ctor(address + CONTROL.title, memory.address(wide))
        return self
    end
    
    function Handle:set_category_icon(index, path, options)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        if not is_integer(index) or index < 1 or index > #self.category_names then
            error("custom_tab: category index is out of range", 2)
        end
        self.category_icons[index] = normalize_embedded_icon(
            path,
            nil,
            nil,
            options,
            2
        )
        self.icon_registry_dirty = true
        return self
    end
    
    function Handle:set_category_icon_data(index, data, source, options)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        if not is_integer(index) or index < 1 or index > #self.category_names then
            error("custom_tab: category index is out of range", 2)
        end
        self.category_icons[index] = normalize_embedded_icon(
            nil,
            data,
            source,
            options,
            2
        )
        self.icon_registry_dirty = true
        return self
    end
    
    function Handle:clear_category_icon(index)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        if not is_integer(index) or index < 1 or index > #self.category_names then
            error("custom_tab: category index is out of range", 2)
        end
        self.category_icons[index] = nil
        self.icon_registry_dirty = true
        return self
    end
    
    local function button_icon_index(self, reference)
        for index = 1, #self.button_icons do
            if self.button_icons[index].reference == reference then
                return index
            end
        end
    end
    
    local function store_button_icon(self, reference, specification, level)
        local mount, address = mounted_control_for_reference(reference)
        if mount == nil then
            error(
                "custom_tab: button icon requires a reference array passed to adopt_tail",
                level or 3
            )
        end
        local control_vtable = u32(address, 0)
        if u8(address, CONTROL.type) ~= BUTTON_TYPE
            or (control_vtable ~= ADDRESS.button_vtable
                and (native == nil or control_vtable ~= native.button_vtable))
        then
            error("custom_tab: configured control is not a native button", level or 3)
        end
    
        local index = button_icon_index(self, reference)
        if index == nil then
            if #self.button_icons >= MAX_BUTTON_ICONS then
                error("custom_tab: button icon limit is " .. MAX_BUTTON_ICONS, level or 3)
            end
            index = #self.button_icons + 1
        end
        self.button_icons[index] = {
            reference = reference,
            mount = mount,
            address = address,
            specification = specification
        }
        self.icon_registry_dirty = true
    end
    
    function Handle:set_button_icon(reference, path, options)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        local specification = normalize_embedded_icon(
            path,
            nil,
            nil,
            options,
            2
        )
        store_button_icon(self, reference, specification, 2)
        return self
    end
    
    function Handle:set_button_icon_data(reference, data, source, options)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        local specification = normalize_embedded_icon(
            nil,
            data,
            source,
            options,
            2
        )
        store_button_icon(self, reference, specification, 2)
        return self
    end
    
    function Handle:clear_button_icon(reference)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        local index = button_icon_index(self, reference)
        if index == nil then
            error("custom_tab: button icon is not configured", 2)
        end
        table.remove(self.button_icons, index)
        self.icon_registry_dirty = true
        return self
    end
    
    function Handle:adopt_tail(target_index, source_index, references)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        validate_mount_target(self, target_index, 2)
        validate_mount_source(source_index, 2)
    
        local count = type(references) == "table" and #references or references
        if not is_integer(count) or count < 1 then
            error("custom_tab: adopted control list must not be empty", 2)
        end
    
        local mount = {
            target_index = target_index,
            source_index = source_index,
            count = count,
            references = type(references) == "table"
                and copy_references(references) or nil,
            active = false
        }
        if not capture_mount_controls(mount, self.saved) then
            error("custom_tab: LUA category is unavailable", 2)
        end
        self.mounts[#self.mounts + 1] = mount
        if self.installed then
            apply_mount(mount, self.saved)
            relayout_categories()
        end
        return self
    end
    
    function Handle:adopt_remaining(target_index, source_index)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        validate_mount_target(self, target_index, 2)
        validate_mount_source(source_index, 2)
    
        local vector = self.saved or available_tab_vector()
        local sources = vector ~= nil and lua_categories(vector) or nil
        local source = sources ~= nil and sources[source_index] or nil
        if source == nil then
            error("custom_tab: LUA category is unavailable", 2)
        end
    
        local begin = u32(source, CATEGORY.controls_begin)
        local finish = u32(source, CATEGORY.controls_end)
        local bytes = finish - begin
        if bytes < 0 or bytes % 4 ~= 0 then
            error("custom_tab: invalid LUA category control vector", 2)
        end
        local baseline = self.source_baselines[source_index] or 0
        local count = bytes / 4 - baseline
        if count < 0 then
            error("custom_tab: LUA category shrank below its ownership baseline", 2)
        end
        if count > 0 then
            self:adopt_tail(target_index, source_index, count)
        end
        return self
    end
    
    function Handle:adopt_tail_groups(source_index, groups)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        validate_mount_source(source_index, 2)
        if type(groups) ~= "table" or #groups < 1 then
            error("custom_tab: mount groups must not be empty", 2)
        end
    
        local prepared = {}
        local total_count = 0
        for index = 1, #groups do
            local group = groups[index]
            if type(group) ~= "table" then
                error("custom_tab: mount group must be a table", 2)
            end
    
            local target_index = group.target_index
            validate_mount_target(self, target_index, 2)
    
            local references = group.references
            if references ~= nil and type(references) ~= "table" then
                error("custom_tab: mount group references must be a table", 2)
            end
            local count = references ~= nil and #references or group.count
            if not is_integer(count) or count < 1 then
                error("custom_tab: mount group must not be empty", 2)
            end
    
            prepared[index] = {
                target_index = target_index,
                count = count,
                references = copy_references(references)
            }
            total_count = total_count + count
        end
    
        local vector = self.saved or available_tab_vector()
        local sources = vector ~= nil and lua_categories(vector) or nil
        local source = sources ~= nil and sources[source_index] or nil
        if source == nil then
            error("custom_tab: LUA category is unavailable", 2)
        end
    
        local begin = u32(source, CATEGORY.controls_begin)
        local finish = u32(source, CATEGORY.controls_end)
        if finish - total_count * 4 < begin then
            error("custom_tab: adopted control count exceeds the LUA category", 2)
        end
    
        local cursor = finish
        local mounts = {}
        for index = 1, #prepared do
            local group = prepared[index]
            local first = cursor - group.count * 4
    
            local mount = {
                target_index = group.target_index,
                source_index = source_index,
                count = group.count,
                references = group.references,
                source = source,
                controls = tail_controls(first, group.count),
                active = false
            }
            self.mounts[#self.mounts + 1] = mount
            mounts[#mounts + 1] = mount
            cursor = first
        end
    
        if self.installed then
            for index = 1, #mounts do
                apply_mount(mounts[index], vector)
            end
            relayout_categories()
        end
        return self
    end
    
    function Handle:configure_category(index, options)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        if not is_integer(index) or index < 1 or index > #self.category_names then
            error("custom_tab: category index is out of range", 2)
        end
        if type(options) ~= "table" then
            error("custom_tab: category options must be a table", 2)
        end
        if options.hide_scrollbar ~= nil
            and type(options.hide_scrollbar) ~= "boolean"
        then
            error("custom_tab: hide_scrollbar must be a boolean", 2)
        end
        if options.lock_layout ~= nil
            and type(options.lock_layout) ~= "boolean"
        then
            error("custom_tab: lock_layout must be a boolean", 2)
        end
        if options.hide_scrollbar == nil and options.lock_layout == nil then
            error(
                "custom_tab: configure_category requires hide_scrollbar or lock_layout",
                2
            )
        end
    
        if options.hide_scrollbar ~= nil then
            self.category_hide_scrollbars[index] = options.hide_scrollbar
            self.icon_registry_dirty = true
        end
        if options.noclip ~= nil then
            if type(options.noclip) ~= "boolean" then
                error("custom_tab: noclip must be a boolean", 2)
            end
            self.category_noclip[index] = options.noclip
            self.icon_registry_dirty = true
        end
        if options.lock_layout ~= nil then
            self.category_layout_locks[index] = options.lock_layout
            local category = self.categories_native[index]
            if category ~= nil then
                put_u8(
                    category.address,
                    CATEGORY.layout_editable,
                    options.lock_layout and 0 or 1
                )
                if options.lock_layout then
                    put_u32(category.address, CATEGORY.layout_mode, 0)
                end
            end
        end
        return self
    end
    
    function Handle:get_category_layouts()
        if self.destroyed then
            error("custom_tab: cannot read a destroyed tab", 2)
        end
        remember_category_layouts()
        local result = {}
        for index = 1, #self.category_names do
            result[index] = self.category_layouts[index]
        end
        return result
    end
    
    function Handle:set_category_layouts(layouts)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        self.category_layouts = normalize_category_layouts(
            layouts,
            #self.category_names,
            2
        )
        if self.installed then
            relayout_categories()
            refresh_listboxes()
        end
        return self
    end
    
    function Handle:get_tab_size()
        if self.destroyed then
            error("custom_tab: cannot read a destroyed tab", 2)
        end
        if not self.installed or self.address == nil then
            error("custom_tab: tab is not installed", 2)
        end
        return u32(self.address, TAB.width), u32(self.address, TAB.height)
    end
    
    function Handle:get_control_rect(reference)
        if self.destroyed then
            error("custom_tab: cannot read a destroyed tab", 2)
        end
        local mount, address = mounted_control_for_reference(reference)
        if mount == nil or not mount.active then
            error("custom_tab: control is not mounted", 2)
        end
    
        local x, y = control_position_in_menu(self, address)
        return
            x,
            y,
            u32(address, CONTROL.width),
            u32(address, CONTROL.height)
    end
    
    function Handle:relayout()
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        if self.installed then
            refresh_listboxes()
            relayout_categories()
        end
        return self
    end
    
    function Handle:configure_listbox(reference, options)
        if self.destroyed then
            error("custom_tab: cannot modify a destroyed tab", 2)
        end
        if type(options) ~= "table" then
            error("custom_tab: listbox options must be a table", 2)
        end
        if options.hide_scrollbar ~= nil then
            error(
                "custom_tab: hide_scrollbar belongs to configure_category",
                2
            )
        end
        if options.fit_items ~= nil and type(options.fit_items) ~= "boolean" then
            error("custom_tab: fit_items must be a boolean", 2)
        end
        if options.hide_header ~= nil and type(options.hide_header) ~= "boolean" then
            error("custom_tab: hide_header must be a boolean", 2)
        end
        local fit_padding = options.fit_padding
        if fit_padding == nil then
            fit_padding = 8
        end
        if not is_integer(fit_padding) or fit_padding < 0 or fit_padding >= 18 then
            error("custom_tab: fit_padding must be an integer from 0 to 17", 2)
        end
    
        local mount, address = mounted_control_for_reference(reference)
        if mount == nil then
            error(
                "custom_tab: configure_listbox requires a reference array passed to adopt_tail",
                2
            )
        end
        if u8(address, CONTROL.type) ~= LISTBOX_TYPE then
            error("custom_tab: configured control is not a native listbox", 2)
        end
        local record
        for index = 1, #self.listboxes do
            if self.listboxes[index].reference == reference then
                record = self.listboxes[index]
                break
            end
        end
        if record == nil then
            record = {
                reference = reference,
                mount = mount,
                address = address,
                original_height = u32(address, CONTROL.height),
                original_intrinsic_height = u32(address, CONTROL.intrinsic_height),
                original_header = u8(address, CONTROL.listbox_header),
                active = false
            }
            self.listboxes[#self.listboxes + 1] = record
        else
            deactivate_listbox(record)
        end
    
        record.fit_items = options.fit_items == true
        record.hide_header = options.hide_header == true
        record.fit_padding = fit_padding
        if mount.active then
            activate_listbox(record, mount.target)
            native.reflow_category(mount.target)
        end
        return self
    end
    
    function Handle:get_size()
        if self.destroyed then
            error("custom_tab: cannot read a destroyed tab", 2)
        end
        remember_menu_size()
        return self.width, self.height
    end
    
    function Handle:set_size(width, height)
        local normalized_width, normalized_height = normalize_size({
            width = width,
            height = height
        }, 2)
        self.width = normalized_width
        self.height = normalized_height
        if self.installed then
            apply_menu_size(self.menu, self.width, self.height)
            refresh_listboxes()
        end
        return self
    end
    
    function Handle:set_icon(path)
        if type(path) ~= "string" or #path == 0 then
            error("custom_tab: icon path must be a non-empty string", 2)
        end
    
        local texture, width, height = load_texture(path)
        self.icon_path = path
        self.icon_data = nil
        self.texture_path = path
        self.texture = texture
        self.texture_source_width = width
        self.texture_source_height = height
        if self.installed then
            apply_icon(self)
        end
        return self
    end
    
    function Handle:set_icon_data(data, source)
        source = source or "<memory>"
        if type(source) ~= "string" or #source == 0 then
            error("custom_tab: icon source must be a non-empty string", 2)
        end
    
        local texture, width, height = load_texture_data(data, source)
        self.icon_path = source
        self.icon_data = data
        self.texture_path = source
        self.texture = texture
        self.texture_source_width = width
        self.texture_source_height = height
        if self.installed then
            apply_icon(self)
        end
        return self
    end
    
    function Handle:set_icon_offset(x, y)
        self.icon_offset_x = normalize_icon_offset(x, "icon_offset_x")
        self.icon_offset_y = normalize_icon_offset(y, "icon_offset_y")
        if self.installed then
            native.state[0].icon_offset_x = self.icon_offset_x
            native.state[0].icon_offset_y = self.icon_offset_y
        end
        return self
    end
    
    function Handle:set_position(position)
        self.position = normalize_position(position)
        if self.installed then
            local restored, restore_error = restore_handle()
            if not restored then
                if lifetime ~= nil then
                    lifetime:close()
                end
                error("custom_tab: position cleanup failed: " .. restore_error, 2)
            end
            local installed, install_error = pcall(install_handle)
            if not installed then
                if lifetime ~= nil then
                    lifetime:close()
                end
                error(install_error, 0)
            end
        end
        return self
    end
    
    function Handle:category(index)
        return self.categories_native[index]
    end
    
    function Handle:category_count()
        return #self.category_names
    end
    
    function Handle:category_has_visible(index)
        if self.destroyed then
            return false
        end
        if not is_integer(index) or index < 1 or index > #self.category_names then
            return false
        end
        local category = self.categories_native[index]
        if category == nil then
            return false
        end
        local address = category.address
        local begin = u32(address, CATEGORY.controls_begin)
        local finish = u32(address, CATEGORY.controls_end)
        local bytes = finish - begin
        if bytes < 4 or bytes % 4 ~= 0 then
            return false
        end
        local pointers = ffi.cast("uint32_t*", begin)
        local count = bytes / 4
        for offset = 0, count - 1 do
            local control = tonumber(pointers[offset])
            if control ~= nil and control ~= 0
                and u8(control, CONTROL.visible) ~= 0
                and u32(control, CONTROL.height) > 8
            then
                return true
            end
        end
        return false
    end
    
    function Handle:destroy()
        if self.destroyed then
            return false
        end
        local restored, restore_error = restore_handle()
        if not restored then
            if lifetime ~= nil then
                lifetime:close()
            end
            error("custom_tab: cleanup failed: " .. restore_error, 2)
        end
        self.destroyed = true
        if handle == self then
            handle = nil
        end
        return true
    end
    
    function Handle:is_ready()
        return self.installed == true
    end
    
    function Handle:is_active()
        return self.installed
            and u32(self.menu, MENU.active) == self.slot
    end
    
    local function on_paint_ui()
        if handle ~= nil
            and not handle.destroyed
            and not handle.installed
            and not handle.installing
        then
            install_handle()
        end
        if handle ~= nil and handle.installed then
            if handle.icon_registry_dpi_scale ~= native_gui_dpi_scale() then
                handle.icon_registry_dirty = true
            end
            if handle.icon_registry_dirty then
                rebuild_icon_registry()
            end
            remember_menu_size()
            remember_category_layouts()
            refresh_listboxes()
        end
    end
    
    local function finalize_handle()
        local owner = handle
        local restored, restore_error = restore_handle()
        if owner ~= nil then
            owner.destroyed = true
        end
        if restored then
            handle = nil
        end
        return restored, restore_error
    end
    
    local function start_runtime()
        cave = nil
        native = nil
        paint_installed = false
        paint_callback = nil
        lifetime = memory.scope(SCRIPT_NAME)
        lifetime:defer(finalize_handle)
    end
    
    local function ensure_runtime()
        if lifetime == nil then
            start_runtime()
            return
        end
        if not lifetime.closed then
            return
        end
        if lifetime.close_ok ~= true then
            error(
                "custom_tab: previous native cleanup is incomplete: "
                    .. table.concat(lifetime.cleanup_errors or {}, "; "),
                3
            )
        end
        start_runtime()
    end
    
    local function report_paint_error(callback_error, close_ok, cleanup_errors)
        local cleanup = ""
        if not close_ok then
            cleanup = "; cleanup incomplete: "
                .. table.concat(cleanup_errors or {}, "; ")
        end
        -- Runtime diagnostics are intentionally silent.
    end
    
    local function install_paint_callback()
        if paint_installed then
            return
        end
    
        local callback = lifetime:guard(on_paint_ui, report_paint_error)
        paint_callback = callback
        lifetime:defer(function()
            if paint_callback ~= callback then
                return true
            end
            if paint_installed then
                local ok, unset_error = pcall(
                    client.unset_event_callback,
                    "paint_ui",
                    callback
                )
                if not ok then
                    return false, unset_error
                end
            end
            paint_installed = false
            paint_callback = nil
            return true
        end)
    
        client.set_event_callback("paint_ui", callback)
        paint_installed = true
    end
    
    function Handle:activate()
        if self.destroyed then
            error("custom_tab: cannot activate a destroyed tab", 2)
        end
        if handle ~= self then
            error("custom_tab: tab is not owned by this Lua state", 2)
        end
        if self.activated then
            return false
        end
    
        local callback_ok, callback_error = pcall(install_paint_callback)
        if not callback_ok then
            local cleanup_ok, cleanup_errors = lifetime:close()
            local cleanup = cleanup_ok and "" or (
                "; cleanup incomplete: " .. table.concat(cleanup_errors or {}, "; ")
            )
            error(tostring(callback_error) .. cleanup, 0)
        end
        self.activated = true
        return true
    end
    
    local custom_tab = {
        version = VERSION,
        default_icon = DEFAULT_ICON,
        default_embedded_icon_size = DEFAULT_EMBEDDED_ICON_SIZE,
        max_categories = MAX_CATEGORIES
    }
    
    function custom_tab.pack_grid(x, y, width, height)
        if not is_integer(x) or not is_integer(y)
            or not is_integer(width) or not is_integer(height)
        then
            error("custom_tab.pack_grid: x, y, width, height must be integers", 2)
        end
        if x < 0 or y < 0 or width < 1 or height < 1
            or x + width > 24 or y + height > 24
        then
            error("custom_tab.pack_grid: layout is outside the 24x24 grid", 2)
        end
        return x + width * 0x100 + y * 0x10000 + height * 0x1000000
    end
    
    function custom_tab.create(options)
        options = options or {}
        if type(options) ~= "table" then
            error("custom_tab.create: options must be a table", 2)
        end
        if options.replace_existing ~= nil
            and type(options.replace_existing) ~= "boolean"
        then
            error("custom_tab: replace_existing must be a boolean", 2)
        end
    
        ensure_runtime()
        if handle ~= nil and not handle.destroyed then
            if options.replace_existing then
                handle:destroy()
            else
                error("custom_tab: this Lua state already owns a custom tab", 2)
            end
        end
    
        local icon_path = options.icon or options.icon_path or DEFAULT_ICON
        if type(icon_path) ~= "string" or #icon_path == 0 then
            error("custom_tab: icon must be a non-empty path", 2)
        end
        local width, height = normalize_size(options.size, 2)
        local category_names, category_definitions = normalize_categories(options.categories)
        local category_icons = {}
        for index = 1, #category_names do
            category_icons[index] = category_icon_from_definition(
                category_definitions[index],
                2
            )
        end
        local category_layouts = normalize_category_layouts(
            options.category_layouts,
            #category_names,
            2
        )
        if #category_layouts == 0 and #category_names > 0 then
            local from_defs = {}
            local complete = true
            for index = 1, #category_names do
                local def = category_definitions[index]
                local grid = def ~= nil and def.grid or nil
                if grid == nil then
                    complete = false
                    break
                end
                from_defs[index] = grid
            end
            if complete then
                category_layouts = normalize_category_layouts(
                    from_defs,
                    #category_names,
                    2
                )
            end
        end
        if #category_layouts == 0 then
            for index = 1, #category_names do
                category_layouts[index] = category_grid(index, #category_names)
            end
        end
    
        local candidate = setmetatable({
            category_names = category_names,
            category_icons = category_icons,
            category_layouts = category_layouts,
            category_hide_scrollbars = {},
            category_noclip = {},
            category_layout_locks = {},
            categories_native = {},
            mounts = {},
            listboxes = {},
            button_icons = {},
            armed_button_vtables = {},
            clipped_tab_vtables = {},
            source_baselines = {0, 0},
            icon_path = icon_path,
            icon_data = options.icon_data,
            icon_offset_x = normalize_icon_offset(options.icon_offset_x, "icon_offset_x"),
            icon_offset_y = normalize_icon_offset(options.icon_offset_y, "icon_offset_y"),
            position = normalize_position(options.position),
            width = width,
            height = height,
            texture = nil,
            texture_path = nil,
            texture_source_width = nil,
            texture_source_height = nil,
            installed = false,
            installing = false,
            inserted = false,
            activated = false,
            destroyed = false,
            icon_registry_dpi_scale = nil,
            icon_registry_dirty = true
        }, Handle)
    
        local vector = available_tab_vector()
        local sources = vector ~= nil and lua_categories(vector) or nil
        if sources == nil or sources[1] == nil or sources[2] == nil then
            error("custom_tab: LUA categories are unavailable", 2)
        end
        for index = 1, 2 do
            local begin = u32(sources[index], CATEGORY.controls_begin)
            local finish = u32(sources[index], CATEGORY.controls_end)
            local bytes = finish - begin
            if bytes < 0 or bytes % 4 ~= 0 then
                error("custom_tab: invalid LUA category control vector", 2)
            end
            candidate.source_baselines[index] = bytes / 4
        end
    
        handle = candidate
        return handle
    end
    
    function custom_tab.get()
        return handle
    end
    
    return custom_tab
    
    end



local ffi = require "ffi"
local bit = require "bit"
local pui = require "gamesense/pui"
local vector = require "vector"
local c_entity = require "gamesense/entity"
local trace = require "gamesense/trace"
local base64 = require "gamesense/base64"
local clipboard = require "gamesense/clipboard"
local database = _G.database
local antiaim_funcs = require "gamesense/antiaim_funcs"
local icons_lib = require "gamesense/icons"
local surface = require "gamesense/surface"
local MENU_ROUTES
local Class = {
 gamesense = {},
 antiaim = {},
 visuals = {},
 network = {},
 motion = {},
 render = {},
 config = {},
 util = {},
 misc = {},
 ui = {}
}

local session_start_time = globals.realtime() or 0
local hitrate_shots = 0
local hitrate_hits = 0
local loader_username = tostring(rawget(_G, "_USERNAME") or "")
loader_username = loader_username:gsub("[%c]", ""):gsub("^%s+", ""):gsub("%s+$", "")
if loader_username == "" then loader_username = "user" end
local user_database = {
 lua_name = "afterglow",
 username = loader_username,
 branch = "Private",
 update_date = "31.07.2026"
}

do
  Class.util = {
   accent_color = {
    first = {140, 110, 115, 255},
   },
  reference = {
   rage_double_tap = { ui.reference("RAGE","aimbot","Double tap")},
   rage_fake_duck = { ui.reference("RAGE", "Other", "Duck peek assist") },
   rage_peek_assist = { ui.reference("RAGE", "Other", "Quick peek assist") },
   aa_enabled = ui.reference("AA", "Anti-aimbot angles", "Enabled"),
   aa_yaw_base = ui.reference("AA", "Anti-aimbot angles", "Yaw base"),
   aa_fs_body_yaw = ui.reference("AA", "Anti-aimbot angles", "Freestanding body yaw"),
   aa_edge_yaw = ui.reference("AA", "Anti-aimbot angles", "Edge yaw"),
   aa_roll = { ui.reference("AA", "Anti-aimbot angles", "Roll") },
   aa_hideshots = { ui.reference("AA","other","on shot anti-aim")},
   aa_pitch = (function()
     local pitch_reference, pitch_value = ui.reference("AA", "Anti-aimbot angles", "Pitch")
     return { pitch_reference, pitch_value }
   end)(),
   aa_yaw = (function()
     local yaw_reference, yaw_value = ui.reference("AA", "Anti-aimbot angles", "Yaw")
     return { yaw_reference, yaw_value }
   end)(),
   aa_yaw_jitter = (function()
     local yaw_jitter_reference, yaw_jitter_value = ui.reference("AA", "Anti-aimbot angles", "Yaw jitter")
     return { yaw_jitter_reference, yaw_jitter_value }
   end)(),
   aa_yaw_body = (function()
     local body_yaw_reference, body_yaw_value = ui.reference("AA", "Anti-aimbot angles", "Body yaw")
     return { body_yaw_reference, body_yaw_value }
   end)(),
   aa_freestanding = { ui.reference("AA", "Anti-aimbot angles", "Freestanding") },
   aa_slow_walk = { ui.reference("AA", "Other", "Slow motion") },
   aa_legs_movement = { ui.reference("AA", "Other", "Leg movement") },
   aa_fakelag_limit = {ui.reference("AA","Fake lag", "Limit")},
   aa_fakelag_variance = {ui.reference("AA","Fake lag", "Variance")},
   aa_fakelag_amount = {ui.reference("AA","Fake lag", "Amount")},
   aa_fakelag_enabled = {ui.reference("AA","Fake lag", "Enabled")},
   aa_fake_peek = { ui.reference("AA", "Other", "Fake peek") },
   visuals_scope_overlay = ui.reference("VISUALS", "Effects", "Remove scope overlay"),
   menu_color = {ui.reference("Misc", "Settings", "Menu color")},
   draw_console_output = ui.reference("Misc", "Miscellaneous", "Draw console output"),
   misc_quick_switch = ui.reference("Misc", "Miscellaneous", "Quick Switch"),
   ping_spike = { ui.reference("Misc", "Miscellaneous", "Ping spike") }
  },
  hide_menu = function(self, show)
    local function vis(reference, v)
      if reference == nil or reference == false then return end
      if type(reference) == "table" then
        for index = 1, #reference do
          if reference[index] ~= nil then pcall(ui.set_visible, reference[index], v) end
        end
      else
      pcall(ui.set_visible, reference, v)
    end
  end
  local r = self.reference
  -- Keep every native Anti-aimbot angles control hidden. Do not briefly
  -- expose these controls during menu refreshes: doing so makes native
  -- sliders re-enter the category layout and can leave blank rows behind.
  local aa_references = {
    r.aa_enabled, r.aa_pitch, r.aa_yaw_base, r.aa_yaw,
    r.aa_yaw_jitter, r.aa_yaw_body, r.aa_fs_body_yaw,
    r.aa_edge_yaw, r.aa_roll, r.aa_freestanding
  }
  for _, reference in pairs(aa_references) do
    if type(reference) == "table" then
      for _, item in pairs(reference) do
        if item ~= nil then pcall(ui.set_visible, item, false) end
      end
    elseif reference ~= nil then
      pcall(ui.set_visible, reference, false)
    end
  end
  vis(r.rage_fake_duck, true)
  vis(r.rage_peek_assist, true)

  if self.aa_tab_notice ~= nil then
    pcall(ui.set_visible, self.aa_tab_notice, self.aa_tab_hidden == true)
  end
end,
sync_macros = function(self)
  pui.macros = pui.macros or {}
  pui.accent = self:rgba_to_hex(
  self.accent_color.first[1],
  self.accent_color.first[2],
  self.accent_color.first[3],
  self.accent_color.first[4]
  )
  pui.macros.dot = "\a4B4B4BFF•\r"
  pui.macros.dot_muted = "\a363636FF•\r"
  pui.macros.dot_accent = string.format("\a%s•\r", pui.accent)
  pui.macros.home = string.format("\a%s\xEE\x84\x8F\r", pui.accent)
  pui.macros.ragebot = string.format("\a%s\r", pui.accent)
  pui.macros.antiaim = string.format("\a%s\r", pui.accent)
  pui.macros.antiaim_conditions = string.format("\a%s\r", pui.accent)
  pui.macros.team = string.format("\a%s\r", pui.accent)
  pui.macros.visuals = string.format("\a%s\xEE\x8A\xB1\r", pui.accent)
  pui.macros.misc = string.format("\a%s\r", pui.accent)
  pui.macros.config = string.format("\a%s\r", pui.accent)
  pui.macros.config_create = string.format("\a%s\r", pui.accent)
  pui.macros.config_load = string.format("\a%s\r", pui.accent)
  pui.macros.config_save = string.format("\a%s\r", pui.accent)
  pui.macros.config_import = string.format("\a%s\r", pui.accent)
  pui.macros.config_export = string.format("\a%s\r", pui.accent)
  pui.macros.config_delete = string.format("\a%s\r", pui.accent)
  pui.macros.antiaim_builder = string.format("\a%s\r", pui.accent)
  pui.macros.antiaim_additional = string.format("\a%s\xEE\x85\xB8\r", pui.accent)
  pui.macros.visuals_interface = string.format("\a%s\r", pui.accent)
  pui.macros.visuals_other = string.format("\a%s\xEE\x85\xB8\r", pui.accent)
  pui.macros.warmup_setup = string.format("\a%s\xEE\x8A\x94\r", pui.accent)
  self._macros_initialized = true
  return true
end,
sync_accent = function(self)
  local reference = self.reference and self.reference.menu_color
  local success, r, g, b, a = false, nil, nil, nil, nil
  if reference then
    pcall(function()
      if type(reference) == "table" then
        if reference[1] then r, g, b, a = ui.get(reference[1]) end
      else
      r, g, b, a = ui.get(reference)
    end
    success = r ~= nil and g ~= nil and b ~= nil
  end)
end
if not success then return false end
r, g, b = math.floor(r), math.floor(g), math.floor(b)
a = a and math.floor(a) or 255
local current = self.accent_color.first
local changed = current[1] ~= r or current[2] ~= g or current[3] ~= b or current[4] ~= a
if changed then
  self.accent_color.first = { r, g, b, a }
end
if changed or not self._macros_initialized then
  self:sync_macros()
end
return changed
end,
open_network_link = function(self)
  local link = "https://discord.gg/CUHpYCamVj"
  pcall(function()
    local network = Class.ui.menu.home_tab.network
    local selected = network and network.choose and tonumber(network.choose:get()) or 1
    if selected == 2 then
      link = "https://t.me/gothsenselua"
    elseif selected == 3 then
      link = "https://www.youtube.com/@%D0%BD%D0%B5%D0%B1%D0%BE%D1%81%D0%B2%D0%BE%D0%B4%D0%B5%D0%BD"
    end
  end)
  panorama.open().SteamOverlayAPI.OpenExternalBrowserURL(link)
end,
_viewmodel_state = nil,
_console_filter_state = nil,
save_viewmodel_state = function(self)
  if self._viewmodel_state then return end
  local success = pcall(function()
    self._viewmodel_state = {
     x = cvar.viewmodel_offset_x:get_float(),
     y = cvar.viewmodel_offset_y:get_float(),
     z = cvar.viewmodel_offset_z:get_float(),
     fov = cvar.viewmodel_fov:get_float()
    }
  end)
  if not success then self._viewmodel_state = nil end
end,
restore_viewmodel = function(self)
  local state = self._viewmodel_state
  if not state then return end
  pcall(function()
    cvar.viewmodel_offset_x:set_raw_float(state.x)
    cvar.viewmodel_offset_y:set_raw_float(state.y)
    cvar.viewmodel_offset_z:set_raw_float(state.z)
    cvar.viewmodel_fov:set_raw_float(state.fov)
  end)
  self._viewmodel_state = nil
end,
setup_console_filter = function(self)
  if not self._console_filter_state then
    local success = pcall(function()
      self._console_filter_state = {
       enabled = cvar.con_filter_enable:get_int(),
       text = cvar.con_filter_text:get_string()
      }
    end)
    if not success then self._console_filter_state = nil end
  end
  pcall(function()
    cvar.con_filter_enable:set_int(1)
    cvar.con_filter_text:set_string("IrWL5106TZZKNFPz4P4Gl3pSN?J370f5hi373ZjPg%VOVh6lN")
  end)
end,
reset_console_filter = function(self)
  local state = self._console_filter_state
  if state then
    pcall(function()
      cvar.con_filter_enable:set_int(state.enabled)
      cvar.con_filter_text:set_string(state.text or "")
    end)
    self._console_filter_state = nil
  end
end,
rgba_to_hex = function(self, r, g, b, a)
  local function byte(v)
    return math.max(0, math.min(255, math.floor((tonumber(v) or 0) + 0.5)))
  end
  return string.format("%02X%02X%02X%02X", byte(r), byte(g), byte(b), byte(a or 255))
end,
get_username = function(self, case)
  return case and string.lower(user_database.username) or user_database.username
end,
get_branch = function(self, case)
  return case and string.lower(user_database.branch) or user_database.branch
end,
chat_print_colored = function(self, parts)
  if type(parts) ~= "table" then return false end
  local success = pcall(function()
    if not self._chat_print_to_chat then
      ffi.cdef[[
      typedef void*** (__thiscall* GothFindHudElement_t)(void*, const char*);
      typedef void (__cdecl* GothChatPrintf_t)(void*, int, int, const char*, ...);
      ]]
      local sig_hud = "\xB9\xCC\xCC\xCC\xCC\x88\x46\x09"
      local sig_find = "\x55\x8B\xEC\x53\x8B\x5D\x08\x56\x57\x8B\xF9\x33\xF6\x39\x77\x28"
      local hud_sig = client.find_signature("client_panorama.dll", sig_hud)
      local find_sig = client.find_signature("client_panorama.dll", sig_find)
      if not hud_sig or not find_sig then error("CHudChat signature not found") end
      local hud = ffi.cast("void**", ffi.cast("char*", hud_sig) + 1)[0]
      if hud == nil then error("hud is nil") end
      local find_hud_element = ffi.cast("GothFindHudElement_t", find_sig)
      local hudchat = find_hud_element(hud, "CHudChat")
      if hudchat == nil or hudchat[0] == nil then error("CHudChat is nil") end
      self._chat_hudchat = hudchat
      self._chat_print_to_chat = ffi.cast("GothChatPrintf_t", hudchat[0][27])
    end
  end)
  if not success or not self._chat_print_to_chat or not self._chat_hudchat then
    return false
  end
  local function color_code(hex)
    hex = tostring(hex or "E1E1E1"):gsub("#", ""):upper()
    if hex == "FF4B5C" then return "\x02" end
    if hex == "9B5CFF" then return "\x0C" end
    return "\x01"
  end
  local output = {}
  for index = 1, #parts do
    local part = parts[index]
    if type(part) == "table" then
      output[#output + 1] = color_code(part.color) .. tostring(part.text or "")
    else
    output[#output + 1] = tostring(part)
  end
end
output[#output + 1] = "\x01"
self._chat_print_to_chat(self._chat_hudchat, 0, 0, table.concat(output))
return true
end,
get_update_date = function(self, case)
  return case and string.lower(user_database.update_date) or user_database.update_date
end,
clamp = function(x, min, max)
  return x < min and min or x > max and max or x
end,
output_message = function(messages)
  for _, part in ipairs(messages) do
    local text = part.text
    local color = part.color
    if text and color then
      client.color_log(color[1] or color.r, color[2] or color.g, color[3] or color.b, text .. "\0")
    end
  end
end,
format_log_prefix = function(self, raw, accent, white, first_color)
  raw = tostring(raw or "")
  local options = {
   custom_prefix = nil,
   use_prefix = true,
   use_brackets = true,
   use_color = true,
   bracket_type = "[]",
  }
  local first = first_color or accent
  local plain = {}
  for token in raw:gmatch("%S+") do
    if token == "nh" then
      options.use_color = false
    elseif token == "nb" then
      options.use_brackets = false
    elseif token == "np" then
      options.use_prefix = false
    elseif token:sub(1, 2) == "p=" then
      options.custom_prefix = token:sub(3)
    elseif token:sub(1, 2) == "b=" then
      local brackets = token:sub(3)
      if brackets ~= "" then
        options.bracket_type = brackets
      end
    else
      plain[#plain + 1] = token
    end
  end

  if options.custom_prefix == nil and #plain > 0 then
    options.custom_prefix = table.concat(plain, " ")
  end
  if options.custom_prefix == nil then
    options.custom_prefix = tostring(user_database.lua_name or "afterglow")
  end
  if not options.use_prefix or options.custom_prefix == "" then
    return {}
  end

  local prefix = tostring(options.custom_prefix)
  local result = {}

  if options.use_brackets and options.bracket_type:sub(1, 1) ~= "" then
    result[#result + 1] = { text = options.bracket_type:sub(1, 1), color = white }
  end

  result[#result + 1] = {
    text = prefix,
    color = options.use_color and first or white
  }

  if options.use_brackets and options.bracket_type:sub(2, 2) ~= "" then
    result[#result + 1] = { text = options.bracket_type:sub(2, 2), color = white }
  end
  result[#result + 1] = { text = " ", color = white }
  return result
end,
}
math.randomseed((globals.frametime() * globals.curtime()) * 100000)
Class.util:hide_menu(false)

-- Keep the native Anti-aimbot angles tab visible, but replace its controls with a notice.
Class.util.aa_tab_notice = ui.new_label(
  "AA",
  "Anti-aimbot angles",
  "Тебе сюда нечего смотреть by Lenora"
)
Class.util.set_aa_tab_hidden = function(self, hidden)
  self.aa_tab_hidden = hidden and true or false
  hidden = self.aa_tab_hidden
  local r = self.reference
  local function set_ref(ref)
    if type(ref) == "table" then
      for _, item in pairs(ref) do
        if item ~= nil then pcall(ui.set_visible, item, not hidden) end
      end
    elseif ref ~= nil then
      pcall(ui.set_visible, ref, not hidden)
    end
  end

  set_ref(r.aa_enabled)
  set_ref(r.aa_pitch)
  set_ref(r.aa_yaw_base)
  set_ref(r.aa_yaw)
  set_ref(r.aa_yaw_jitter)
  set_ref(r.aa_yaw_body)
  set_ref(r.aa_fs_body_yaw)
  set_ref(r.aa_edge_yaw)
  set_ref(r.aa_roll)
  set_ref(r.aa_freestanding)
  if self.aa_tab_notice ~= nil then
    pcall(ui.set_visible, self.aa_tab_notice, hidden)
  end
end
Class.util:set_aa_tab_hidden(true)
end

do
  Class.motion.exponential_smooth = function(current, target, factor)
    factor = factor or 0.15
    local delta_time = globals.frametime()
    local time_factor = 1 - math.exp(-factor * delta_time * 60)
    return current + (target - current) * time_factor
  end
  Class.motion.interpolation = function(a, b, t)
    if type(b) == "boolean" then b = b and 1 or 0 end
    local delta = globals.frametime()
    if delta >= t then return b end
    return a + (b - a) * (delta / t)
  end
  Class.motion.window = function(current, target, factor)
    if current == nil then return target end
    return Class.motion.exponential_smooth(current, target, factor or 0.28)
  end
end

do
  local screen_w, screen_h = client.screen_size()
  screen_w, screen_h = screen_w or 1920, screen_h or 1080
  local refs = {
   wm_x    = ui.new_slider("LUA", "B", "afterglow window watermark x", 0, 7680, math.floor(screen_w / 2)),
   wm_y    = ui.new_slider("LUA", "B", "afterglow window watermark y", 0, 4320, math.floor(screen_h - 20)),
   slow_x  = ui.new_slider("LUA", "B", "afterglow window velocity x", 0, 7680, math.floor(screen_w / 2 - 75)),
   slow_y  = ui.new_slider("LUA", "B", "afterglow window velocity y", 0, 4320, math.floor(screen_h * 0.35)),
    dmg_x   = ui.new_slider("LUA", "B", "afterglow window damage x", 0, 7680, math.floor(screen_w / 2 + 20)),
    dmg_y   = ui.new_slider("LUA", "B", "afterglow window damage y", 0, 4320, math.floor(screen_h / 2 - 30)),
   base_w  = ui.new_slider("LUA", "B", "afterglow window base w", 640, 7680, screen_w),
   base_h  = ui.new_slider("LUA", "B", "afterglow window base h", 480, 4320, screen_h),
  }
  for _, reference in pairs(refs) do pcall(ui.set_visible, reference, false) end
  Class.util.window_pos = {
   refs = {
    wm = { x = refs.wm_x, y = refs.wm_y },
    slow = { x = refs.slow_x, y = refs.slow_y },
     dmg = { x = refs.dmg_x, y = refs.dmg_y },
   },
   base_w = refs.base_w,
   base_h = refs.base_h,
   _last_sw = nil,
   _last_sh = nil,
  _keys = {
   wm_x = "wm", wm_y = "wm",
   slow_x = "slow", slow_y = "slow",
    dmg_x = "dmg", dmg_y = "dmg",
  },
  _screen = function(self)
    local sw, sh = client.screen_size()
    sw, sh = tonumber(sw) or 0, tonumber(sh) or 0
    if sw < 64 or sh < 64 then return nil, nil end
    return sw, sh
  end,
  _clamp_xy = function(self, x, y, sw, sh)
    x = math.floor(tonumber(x) or 0)
    y = math.floor(tonumber(y) or 0)
    if sw then x = math.max(0, math.min(sw - 1, x)) end
    if sh then y = math.max(0, math.min(sh - 1, y)) end
    x = math.max(0, math.min(7680, x))
    y = math.max(0, math.min(4320, y))
    return x, y
  end,
  get = function(self, key_x, key_y, default_x, default_y)
    local pair = self.refs[self._keys[key_x]]
    if not pair then return default_x, default_y end
    local x, y = tonumber(ui.get(pair.x)), tonumber(ui.get(pair.y))
    if x == nil or y == nil then return default_x, default_y end
    local sw, sh = self:_screen()
    local base_w = tonumber(ui.get(self.base_w)) or sw or 1920
    local base_h = tonumber(ui.get(self.base_h)) or sh or 1080
    if sw and sh and base_w > 0 and base_h > 0 and (base_w ~= sw or base_h ~= sh) then
      x = x * (sw / base_w)
      y = y * (sh / base_h)
      x, y = self:_clamp_xy(x, y, sw, sh)
      pcall(ui.set, pair.x, x)
      pcall(ui.set, pair.y, y)
      pcall(ui.set, self.base_w, sw)
      pcall(ui.set, self.base_h, sh)
    else
      x, y = self:_clamp_xy(x, y, sw, sh)
    end
    return x, y
  end,
  set = function(self, key_x, key_y, x, y)
    local pair = self.refs[self._keys[key_x]]
    if not pair or x == nil or y == nil then return end
    local sw, sh = self:_screen()
    x, y = self:_clamp_xy(x, y, sw, sh)
    pcall(ui.set, pair.x, x)
    pcall(ui.set, pair.y, y)
    if sw and sh then
      pcall(ui.set, self.base_w, sw)
      pcall(ui.set, self.base_h, sh)
      self._last_sw, self._last_sh = sw, sh
    end
  end,
  export = function(self)
    local output = {}
    local pairs_map = {
     {"wm_x", "wm_y"}, {"slow_x", "slow_y"}, {"dmg_x", "dmg_y"},
    }
    local sw, sh = self:_screen()
    local base_w = tonumber(ui.get(self.base_w)) or sw or 1920
    local base_h = tonumber(ui.get(self.base_h)) or sh or 1080
    for index = 1, #pairs_map do
      local kx, ky = pairs_map[index][1], pairs_map[index][2]
      local pair = self.refs[self._keys[kx]]
      if pair then
        local x, y = tonumber(ui.get(pair.x)), tonumber(ui.get(pair.y))
        if x ~= nil and y ~= nil then
          output[kx], output[ky] = x, y
        end
      end
    end
    output.base_w = base_w
    output.base_h = base_h
    return output
  end,
  import = function(self, data)
    if type(data) ~= "table" then return end
    local sw, sh = self:_screen()
    local src_w = tonumber(data.base_w)
    local src_h = tonumber(data.base_h)
    local pairs_map = {
     {"wm_x", "wm_y"}, {"slow_x", "slow_y"}, {"dmg_x", "dmg_y"},
    }
    for index = 1, #pairs_map do
      local kx, ky = pairs_map[index][1], pairs_map[index][2]
      if data[kx] ~= nil and data[ky] ~= nil then
        local x, y = tonumber(data[kx]), tonumber(data[ky])
        if x and y and sw and sh and src_w and src_h and src_w > 0 and src_h > 0 then
          x = x * (sw / src_w)
          y = y * (sh / src_h)
        end
        self:set(kx, ky, x, y)
      end
    end
  end,
  sync_resolution = function(self)
    local sw, sh = self:_screen()
    if not sw or not sh then return end
    if self._last_sw and self._last_sh and (self._last_sw ~= sw or self._last_sh ~= sh) then
      local sx = sw / self._last_sw
      local sy = sh / self._last_sh
      for _, pair in pairs(self.refs) do
        local x = tonumber(ui.get(pair.x)) or 0
        local y = tonumber(ui.get(pair.y)) or 0
        x, y = self:_clamp_xy(x * sx, y * sy, sw, sh)
        pcall(ui.set, pair.x, x)
        pcall(ui.set, pair.y, y)
      end
      pcall(ui.set, self.base_w, sw)
      pcall(ui.set, self.base_h, sh)
      self:apply_live()
    elseif not self._last_sw then
      -- first frame / load: scale from saved base resolution into current screen
      local base_w = tonumber(ui.get(self.base_w)) or sw
      local base_h = tonumber(ui.get(self.base_h)) or sh
      if base_w > 0 and base_h > 0 and (base_w ~= sw or base_h ~= sh) then
        local sx = sw / base_w
        local sy = sh / base_h
        for _, pair in pairs(self.refs) do
          local x = tonumber(ui.get(pair.x)) or 0
          local y = tonumber(ui.get(pair.y)) or 0
          x, y = self:_clamp_xy(x * sx, y * sy, sw, sh)
          pcall(ui.set, pair.x, x)
          pcall(ui.set, pair.y, y)
        end
        pcall(ui.set, self.base_w, sw)
        pcall(ui.set, self.base_h, sh)
        self:apply_live()
      end
    end
    self._last_sw, self._last_sh = sw, sh
  end,
  apply_live = function(self)
    local function apply_position(object, x_key, y_key, default_x, default_y)
      if not object then return end
      local screen_width, screen_height = self:_screen()
      if not screen_width then return end
      local x, y = self:get(x_key, y_key, default_x(screen_width, screen_height), default_y(screen_width, screen_height))
      if object.target_pos then object.target_pos.x, object.target_pos.y = x, y end
      if object.pos then object.pos.x, object.pos.y = x, y end
    end
    apply_position(Class.visuals.watermark_ui, "wm_x", "wm_y", function(w, h) return w * 0.57 end, function(w, h) return h * 0.76 end)
    apply_position(Class.visuals.velocity_indicator, "slow_x", "slow_y", function(w, h) return w / 2 - 75 end, function(w, h) return h * 0.35 end)
    apply_position(Class.visuals.damage_indicator, "dmg_x", "dmg_y", function(w, h) return w / 2 + 20 end, function(w, h) return h / 2 - 30 end)
  end,
  bind = function(self)
    if self._bound then return end
    local function refresh() self:apply_live() end
    for _, pair in pairs(self.refs) do
      pcall(ui.set_callback, pair.x, refresh)
      pcall(ui.set_callback, pair.y, refresh)
    end
    pcall(client.set_event_callback, "paint", function()
      self:sync_resolution()
    end)
    self._bound = true
  end,
  }
end

do
  local function hid_slider(label, minv, maxv, def)
    local reference = ui.new_slider("LUA", "B", label, minv, maxv, def)
    pcall(ui.set_visible, reference, false)
    return reference
  end
  Class.util.viewmodel_store = {
   en  = hid_slider("afterglow vm en", 0, 1, 0),
   fov = hid_slider("afterglow vm fov", 540, 900, 680),
   x   = hid_slider("afterglow vm x", -200, 200, 0),
   y   = hid_slider("afterglow vm y", -200, 200, 0),
   z   = hid_slider("afterglow vm z", -200, 200, 0),
   knife = hid_slider("afterglow vm knife", 0, 1, 0),
   initialized = hid_slider("afterglow vm init", 0, 1, 0),
   _applying = false,
   _hooked = false,
   save = function(self)
     if self._applying then return end
     local viewmodel_changer = Class.ui.menu and Class.ui.menu.visuals_tab and Class.ui.menu.visuals_tab.other and Class.ui.menu.visuals_tab.other.viewmodel_changer
     if not viewmodel_changer then return end
     local en = viewmodel_changer.enabled:get() and 1 or 0
     local fov = math.floor(tonumber(viewmodel_changer.fov:get()) or 680)
     local x = math.floor(tonumber(viewmodel_changer.position.x:get()) or 0)
     local y = math.floor(tonumber(viewmodel_changer.position.y:get()) or 0)
     local z = math.floor(tonumber(viewmodel_changer.position.z:get()) or 0)
     local knife = 0
     pcall(function()
       knife = viewmodel_changer.features and viewmodel_changer.features:get("Opposite Knife Hand") and 1 or 0
     end)
     fov = math.max(540, math.min(900, fov))
     x = math.max(-200, math.min(200, x))
     y = math.max(-200, math.min(200, y))
     z = math.max(-200, math.min(200, z))
     pcall(ui.set, self.en, en)
     pcall(ui.set, self.fov, fov)
     pcall(ui.set, self.x, x)
     pcall(ui.set, self.y, y)
     pcall(ui.set, self.z, z)
     pcall(ui.set, self.knife, knife)
     pcall(ui.set, self.initialized, 1)
   end,
   load = function(self)
     local viewmodel_changer = Class.ui.menu and Class.ui.menu.visuals_tab and Class.ui.menu.visuals_tab.other and Class.ui.menu.visuals_tab.other.viewmodel_changer
     if not viewmodel_changer then return end
     local init = ui.get(self.initialized) or 0
     if init ~= 1 then return end
     local en = ui.get(self.en) or 0
     local fov = ui.get(self.fov) or 680
     local x = ui.get(self.x) or 0
     local y = ui.get(self.y) or 0
     local z = ui.get(self.z) or 0
     local knife = ui.get(self.knife) or 0
     self._applying = true
     pcall(function()
       if en ~= nil then viewmodel_changer.enabled:set(en == 1 or en == true) end
       if fov ~= nil then viewmodel_changer.fov:set(tonumber(fov) or 680) end
       if x ~= nil then viewmodel_changer.position.x:set(tonumber(x) or 0) end
       if y ~= nil then viewmodel_changer.position.y:set(tonumber(y) or 0) end
       if z ~= nil then viewmodel_changer.position.z:set(tonumber(z) or 0) end
       if knife ~= nil and viewmodel_changer.features then
         local selected = {}
         pcall(function() selected = viewmodel_changer.features:get() or {} end)
         local has = {}
         if type(selected) == "table" then
           for i = 1, #selected do has[selected[i]] = true end
         end
         has["Opposite Knife Hand"] = knife == 1 or knife == true
         local next_selected = {}
         if has["Opposite Knife Hand"] then next_selected[#next_selected + 1] = "Opposite Knife Hand" end
         if has["Remove Sleeves"] then next_selected[#next_selected + 1] = "Remove Sleeves" end
         if has["Lock Bob"] then next_selected[#next_selected + 1] = "Lock Bob" end
         viewmodel_changer.features:set(next_selected)
       end
     end)
     self._applying = false
   end,
   hook = function(self)
     if self._hooked then return end
     local viewmodel_changer = Class.ui.menu and Class.ui.menu.visuals_tab and Class.ui.menu.visuals_tab.other and Class.ui.menu.visuals_tab.other.viewmodel_changer
     if not viewmodel_changer then return end
     local function snap()
       if Class.util.viewmodel_store then Class.util.viewmodel_store:save() end
     end
     pcall(function()
       if viewmodel_changer.enabled.set_callback then viewmodel_changer.enabled:set_callback(snap) end
       if viewmodel_changer.fov.set_callback then viewmodel_changer.fov:set_callback(snap) end
       if viewmodel_changer.position.x.set_callback then viewmodel_changer.position.x:set_callback(snap) end
       if viewmodel_changer.position.y.set_callback then viewmodel_changer.position.y:set_callback(snap) end
       if viewmodel_changer.position.z.set_callback then viewmodel_changer.position.z:set_callback(snap) end
       if viewmodel_changer.features and viewmodel_changer.features.set_callback then
         viewmodel_changer.features:set_callback(snap)
       end
     end)
     self._hooked = true
   end,
  }
end

do
  Class.util.snap_drag = {
   threshold = 10,
   guides = { v = false, h = false },
    apply = function(self, x, y, w, h, anchor, show_guides)
     local screen_width, screen_height = client.screen_size()
     if show_guides == nil then show_guides = true end
     local center_x, center_y = screen_width * 0.5, screen_height * 0.5
     w, h = w or 0, h or 0
     anchor = anchor or "topleft"
     local el_cx, el_cy
     if anchor == "bottom_center" then
       el_cx = x
       el_cy = y - h * 0.5
     elseif anchor == "center" then
       el_cx, el_cy = x, y
     else
     el_cx = x + w * 0.5
     el_cy = y + h * 0.5
   end
   local snap_v, snap_h = false, false
   if math.abs(el_cx - center_x) <= self.threshold then
     snap_v = true
     if anchor == "bottom_center" or anchor == "center" then
       x = center_x
     else
     x = center_x - w * 0.5
   end
 end
 if math.abs(el_cy - center_y) <= self.threshold then
   snap_h = true
   if anchor == "bottom_center" then
     y = center_y + h * 0.5
   elseif anchor == "center" then
     y = center_y
   else
   y = center_y - h * 0.5
 end
 end
 if show_guides then
   if snap_v then self.guides.v = true end
   if snap_h then self.guides.h = true end
 end
 return x, y
 end,
 begin_frame = function(self)
   self.guides.v = false
   self.guides.h = false
 end,
 draw = function(self)
   if not ui.is_menu_open() then return end
   if not client.key_state(0x01) then return end
   if not self.guides.v and not self.guides.h then return end
   local screen_width, screen_height = client.screen_size()
   local center_x = math.floor(screen_width * 0.5 + 0.5)
   local center_y = math.floor(screen_height * 0.5 + 0.5)
   if self.guides.v then
     renderer.line(center_x, 0, center_x, screen_height, 255, 255, 255, 90)
     renderer.line(center_x + 1, 0, center_x + 1, screen_height, 255, 255, 255, 40)
   end
   if self.guides.h then
     renderer.line(0, center_y, screen_width, center_y, 255, 255, 255, 90)
     renderer.line(0, center_y + 1, screen_width, center_y + 1, 255, 255, 255, 40)
   end
   if self.guides.v or self.guides.h then
     local s = 6
     renderer.line(center_x - s, center_y, center_x + s, center_y, 255, 255, 255, 160)
     renderer.line(center_x, center_y - s, center_x, center_y + s, 255, 255, 255, 160)
   end
 end,
}
end
do

  Class.render.notifications = {
  config = {
    max_items = 5,
    lifetime = 3.0,
    corner_radius = 5,
    background_alpha = 175,
    text_flags = "",
    stack_gap = 4,
  },

  items = {},
  pos = {x = nil, y = nil},
  target_pos = {x = nil, y = nil},
  _clamp = function(self, value, min_value, max_value)
    value = tonumber(value) or min_value
    if value < min_value then return min_value end
    if value > max_value then return max_value end
    return value
  end,

  _smooth = function(self, current, target, speed)
    local dt = tonumber(globals.frametime()) or 0
    if dt <= 0 then dt = 1 / 60 end
    dt = math.min(dt, 0.05)
    local factor = 1 - math.exp(-(speed or 14) * dt)
    return current + (target - current) * factor
  end,

  _body_parts = function(self, item)
    local base_text = {240, 240, 240, 255}
    local accent = item.color or base_text
    local text = item.raw_text or ""
    local parts = {}
    local current_color = base_text
    local pos = 1

    while true do
      local marker_start, marker_end = text:find("/[vr]", pos)
      if not marker_start then
        local tail = text:sub(pos)
        if tail ~= "" then
          parts[#parts + 1] = {text = tail, color = current_color}
        end
        break
      end

      local chunk = text:sub(pos, marker_start - 1)
      if chunk ~= "" then
        parts[#parts + 1] = {text = chunk, color = current_color}
      end

      local marker = text:sub(marker_start, marker_end)
      current_color = marker == "/v" and accent or base_text
      pos = marker_end + 1
    end

    if #parts == 0 and text ~= "" then
      parts[1] = {text = text, color = base_text}
    end
    return parts
  end,

  _measure_parts = function(self, parts)
    local width, height = 0, 0
    local flags = self.config.text_flags
    for index = 1, #parts do
      local part = parts[index]
      if part.text and part.text ~= "" then
        local w, h = renderer.measure_text(flags, part.text)
        width = width + (w or 0)
        height = math.max(height, h or 0)
      end
    end
    return width, math.max(height, 11)
  end,

  _rounded = function(self, x, y, w, h, radius, r, g, b, a)
    -- non-overlapping pieces so alpha does not stack darker at corners/icon side
    if a <= 0 then return end
    x, y, w, h = math.floor(x + 0.5), math.floor(y + 0.5), math.floor(w + 0.5), math.floor(h + 0.5)
    radius = math.floor(self:_clamp(radius, 0, math.min(w, h) * 0.5) + 0.5)

    if radius <= 1 then
      renderer.rectangle(x, y, w, h, r, g, b, a)
      return
    end

    renderer.rectangle(x + radius, y + radius, w - radius * 2, h - radius * 2, r, g, b, a)
    renderer.rectangle(x + radius, y, w - radius * 2, radius, r, g, b, a)
    renderer.rectangle(x + radius, y + h - radius, w - radius * 2, radius, r, g, b, a)
    renderer.rectangle(x, y + radius, radius, h - radius * 2, r, g, b, a)
    renderer.rectangle(x + w - radius, y + radius, radius, h - radius * 2, r, g, b, a)
    renderer.circle(x + radius, y + radius, r, g, b, a, radius, 180, 0.25)
    renderer.circle(x + w - radius, y + radius, r, g, b, a, radius, 90, 0.25)
    renderer.circle(x + w - radius, y + h - radius, r, g, b, a, radius, 0, 0.25)
    renderer.circle(x + radius, y + h - radius, r, g, b, a, radius, 270, 0.25)
  end,

  _outline = function(self, x, y, w, h, radius, r, g, b, a)
    -- true 1px rounded outline (does NOT fill center — fill must be drawn separately)
    if a <= 0 then return end
    x, y, w, h = math.floor(x + 0.5), math.floor(y + 0.5), math.floor(w + 0.5), math.floor(h + 0.5)
    radius = math.floor(self:_clamp(radius, 0, math.min(w, h) * 0.5) + 0.5)
    if radius <= 1 then
      renderer.rectangle(x, y, w, 1, r, g, b, a)
      renderer.rectangle(x, y + h - 1, w, 1, r, g, b, a)
      renderer.rectangle(x, y, 1, h, r, g, b, a)
      renderer.rectangle(x + w - 1, y, 1, h, r, g, b, a)
      return
    end
    -- edges
    renderer.rectangle(x + radius, y, w - radius * 2, 1, r, g, b, a)
    renderer.rectangle(x + radius, y + h - 1, w - radius * 2, 1, r, g, b, a)
    renderer.rectangle(x, y + radius, 1, h - radius * 2, r, g, b, a)
    renderer.rectangle(x + w - 1, y + radius, 1, h - radius * 2, r, g, b, a)
    pcall(function()
      renderer.circle_outline(x + radius, y + radius, r, g, b, a, radius, 180, 0.25)
      renderer.circle_outline(x + w - radius, y + radius, r, g, b, a, radius, 90, 0.25)
      renderer.circle_outline(x + w - radius, y + h - radius, r, g, b, a, radius, 0, 0.25)
      renderer.circle_outline(x + radius, y + h - radius, r, g, b, a, radius, 270, 0.25)
    end)
  end,

  _icon = function(self, x, y, r, g, b, a, notification_type)
    if (tonumber(a) or 0) <= 0 then return end
    local rr = math.max(0, math.min(255, math.floor(tonumber(r) or 255)))
    local gg = math.max(0, math.min(255, math.floor(tonumber(g) or 255)))
    local bb = math.max(0, math.min(255, math.floor(tonumber(b) or 255)))
    local alpha = math.max(0, math.min(255, math.floor(tonumber(a) or 255)))
    local icon_size = 12

    local kind = tostring(notification_type or "info"):lower():gsub("[%s%-]+", "_")
    local icon_specs = self._notification_icon_specs
    if not icon_specs then
      -- NL gasolina-style: antibrute = sparkles, default hit-ish = bolt
      icon_specs = {
        hit = {"bolt", "outline"},
        miss = {"x-circle", "outline"},
        connection = {"sparkles", "outline"},
        antibrute = {"sparkles", "outline"},
        antibrute_reset = {"sparkles", "outline"},
        config_success = {"check", "outline"},
        config_error = {"x-mark", "outline"},
        info = {"sparkles", "outline"},
      }
      self._notification_icon_specs = icon_specs
    end

    local spec = icon_specs[kind]
    if not spec then return end
    local name, style = spec[1], spec[2]
    local textures = self._notification_icon_textures
    local requested = self._notification_icon_requested
    if not textures then textures = {}; self._notification_icon_textures = textures end
    if not requested then requested = {}; self._notification_icon_requested = requested end
    local key = name .. ":" .. style .. ":" .. tostring(icon_size)

    if not textures[key] and not requested[key] then
      requested[key] = true
      icons_lib.hero.get_texture(name, style, {255, 255, 255, 255}, icon_size, function(texture)
        if texture then textures[key] = texture end
      end)
    end

    local icon = textures[key]
    local draw_x = math.floor(x - icon_size * 0.5 + 0.5)
    local draw_y = math.floor(y - icon_size * 0.5 + 0.5)
    if icon then
      renderer.texture(icon, draw_x, draw_y, icon_size, icon_size, rr, gg, bb, alpha)
      return
    end

    -- No text or Unicode fallback: if the Heroicon texture is unavailable, draw nothing.
  end,

  is_active = function(self)
    local active = false
    pcall(function()
      local logger = Class.ui.menu.misc_tab.event_logger
      active = logger and logger.enabled:get()
        and logger.triggers
        and logger.triggers.event_triggers:get("On Screen") == true or false
    end)
    if not active then
      pcall(function()
        local ab = Class.ui.menu.antiaim_tab.additional.fakelag.anti_bruteforce
        active = ab and ab.enabled:get()
          and ab.notify
          and ab.notify:get("On Screen") == true or false
      end)
    end
    return active
  end,

  push = function(self, text, notif_type)
    local notification_kind = tostring(notif_type or "info")
    if not self:is_active() then return end

    local menu_bg = {0, 0, 0, 255}
    -- on-screen colors follow menu accent; event logger colors are separate
    local menu_accent = Class.util.accent_color and Class.util.accent_color.first or {222, 206, 168, 255}
    local accent_col = {
      menu_accent[1] or 222,
      menu_accent[2] or 206,
      menu_accent[3] or 168,
      menu_accent[4] or 255,
    }
    -- pure red #FF0000 accent for reset / miss / connection (body stays white)
    local pure_red = {255, 0, 0, 255}
    if notification_kind == "antibrute_reset"
      or notification_kind == "miss"
      or notification_kind == "connection" or notification_kind == "config_error" then
      accent_col = pure_red
    end

    table.insert(self.items, 1, {
      time = globals.realtime(),
      raw_text = type(text) == "string" and text or tostring(text or ""),
      color = accent_col,
      bg_color = menu_bg,
      type = notif_type or "info",
      opacity = 0,
      y_offset = 4,
    })

    while #self.items > self.config.max_items do
      table.remove(self.items)
    end
  end,

  clear = function(self)
    self.items = {}
  end,

  render = function(self)
    local now = globals.realtime()
    local cfg = self.config
    local menu = Class.ui.menu.visuals_tab.other.notifications

    if menu then
      pcall(function()
        local life_raw = tonumber(menu.lifetime:get()) or 30
        -- slider uses 0.1 display scale: 30 -> 3.0s
        cfg.lifetime = math.max(0.5, life_raw * 0.1)
        cfg.max_items = math.max(1, math.floor(tonumber(menu.max_items:get()) or cfg.max_items))
      end)
    end

    for index = #self.items, 1, -1 do
      local item = self.items[index]
      local age = now - item.time
      local target = age < cfg.lifetime and 1 or 0
      item.opacity = self:_smooth(item.opacity, target, target > item.opacity and 22 or 10)
      local entering = age < 0.45 and target > 0
      if entering then
        item.y_offset = self:_smooth(item.y_offset or 4, 0, 20)
      else
        item.y_offset = self:_smooth(item.y_offset or 0, 0, 20)
      end
      if age > cfg.lifetime + 0.9 and item.opacity < 0.01 then
        table.remove(self.items, index)
      end
    end

    if #self.items == 0 then return end

    local sw, sh = client.screen_size()
    sw, sh = tonumber(sw) or 0, tonumber(sh) or 0
    if sw < 64 or sh < 64 then return end
    local y_off = 80
    if menu then
      pcall(function() y_off = tonumber(menu.y_offset:get()) or 80 end)
    end
    y_off = self:_clamp(y_off, 0, sh)
    self.target_pos.x = math.floor(sw * 0.5)
    self.target_pos.y = math.floor(sh - y_off)
    local res_changed = self._last_sw ~= sw or self._last_sh ~= sh
    if not self.pos.x or not self.pos.y or res_changed then
      self.pos.x = self.target_pos.x
      self.pos.y = self.target_pos.y
      self._last_sw, self._last_sh = sw, sh
    else
      self.pos.x = self:_smooth(self.pos.x, self.target_pos.x, 18)
      self.pos.y = self:_smooth(self.pos.y, self.target_pos.y, 18)
    end

    local pad_left = 11
    local pad_right = 11
    local bottom = self.pos.y

    for index = 1, #self.items do
      local item = self.items[index]
      local body_parts = self:_body_parts(item)
      local body_w, body_h = self:_measure_parts(body_parts)
      local card_h = math.max(26, math.max(14, body_h) + 11)
      local card_w = math.max(pad_left + 24 + body_w + pad_right, 90)
      local target_y = bottom - card_h
      item.y = self:_smooth(item.y or target_y, target_y, 20)
      bottom = target_y - cfg.stack_gap

      local x = math.floor(self.pos.x - card_w * 0.5 + 0.5)
      local y = math.floor(item.y + (item.y_offset or 0) + 0.5)
      local radius = math.min(cfg.corner_radius, card_h * 0.5, card_w * 0.5)
      local opacity = self:_clamp(item.opacity, 0, 1)
      local bg = item.bg_color or {0, 0, 0, 255}
      local accent = item.color or {255, 255, 255, 255}
      -- gasolina: fill black a120, true outline (not filled under the card)
      local bg_a = math.floor(175 * opacity + 0.5)
      local fg_a = math.floor(255 * opacity + 0.5)

      if bg_a > 0 then
        -- outer rounded shell (border) then inner fill — corners match radius
        local ol_a = math.floor(200 * opacity + 0.5)
        self:_rounded(x - 1, y - 1, card_w + 2, card_h + 2, radius + 1, 70, 70, 70, ol_a)
        self:_rounded(x, y, card_w, card_h, radius,
          bg[1] or 0, bg[2] or 0, bg[3] or 0, bg_a)
      end

      if fg_a > 0 then
        local center_y = math.floor(y + card_h * 0.5 + 0.5)
        local prefix_x = math.floor(x + pad_left + 0.5)
        local icon_size, icon_gap = 12, 5
        local separator_width, separator_height = 2, 14
        local icon_cx = prefix_x + icon_size * 0.5
        local icon_alpha = math.floor((accent[4] or 255) * opacity + 0.5)
        self:_icon(icon_cx, center_y, accent[1] or 255, accent[2] or 255,
          accent[3] or 255, icon_alpha, item.type)
        local separator_x = math.floor(prefix_x + icon_size + icon_gap + 0.5)
        local separator_y = math.floor(center_y - separator_height * 0.5 + 0.5)
        renderer.rectangle(separator_x, separator_y, separator_width, separator_height,
          240, 240, 240, icon_alpha)

        local text_x = prefix_x + icon_size + icon_gap * 2 + separator_width
        local text_y = math.floor(center_y - body_h * 0.5 + 0.5)
        for part_index = 1, #body_parts do
          local part = body_parts[part_index]
          local part_text = part.text or ""
          if part_text ~= "" then
            local c = part.color or {240, 240, 240, 255}
            local a = math.floor((c[4] or 255) * opacity + 0.5)
            renderer.text(math.floor(text_x + 0.5), text_y,
              c[1] or 240, c[2] or 240, c[3] or 240, a,
              cfg.text_flags, 0, part_text)
            text_x = text_x + (select(1, renderer.measure_text(cfg.text_flags, part_text)) or 0)
          end
        end
      end
    end
  end,
}
end

local function utf8_chars(str)
  local chars = {}
  local index = 1
  while index <= #str do
    local byte = str:byte(index)
    local char_len
    if byte < 128 then char_len = 1
    elseif byte < 224 then char_len = 2
    elseif byte < 240 then char_len = 3
    else char_len = 4 end
    table.insert(chars, str:sub(index, index + char_len - 1))
    index = index + char_len
  end
  return chars
end
Class.render.gradient_text = function(str, speed, direction, r, g, b, a, r2, g2, b2, a2, progress_offset, total_length, time_value)
  speed = speed or 1
  direction = direction or "Right"
  r, g, b, a = r or 255, g or 255, b or 255, a or 255
  r2, g2, b2, a2 = r2 or 255, g2 or 255, b2 or 255, a2 or 255
  local r_add, g_add, b_add, a_add = r2 - r, g2 - g, b2 - b, a2 - a
  local chars = utf8_chars(str)
  local length = #chars
  local denominator = math.max((tonumber(total_length) or length) - 1, 1)
  local offset = tonumber(progress_offset) or 0
  local animation_time = tonumber(time_value) or globals.curtime()
  local t_out = {}
  for index = 1, length do
    local progress = (offset + index - 1) / denominator
    local iter = progress + animation_time * speed * (direction == "Right" and -1 or 1)
    local color_factor = math.abs(math.cos(iter))
    local cr = r + r_add * color_factor
    local cg = g + g_add * color_factor
    local cb = b + b_add * color_factor
    local ca = a + a_add * color_factor
    t_out[#t_out + 1] = "\a" .. Class.util:rgba_to_hex(cr, cg, cb, ca)
    t_out[#t_out + 1] = chars[index]
  end
  return table.concat(t_out)
end
Class.render.rainbow_text = function(text, speed, direction, a, saturation, progress_offset, total_length)
  if type(text) ~= "string" or text == "" then
    return ""
  end

  local chars = utf8_chars(text)
  local length = #chars
  local denominator = math.max((tonumber(total_length) or length) - 1, 1)
  local offset = tonumber(progress_offset) or 0
  local out = {}
  local sat = math.max(0, math.min(1, tonumber(saturation) or 1))
  local alpha = math.max(0, math.min(255, math.floor(tonumber(a) or 255)))
  local animation_speed = tonumber(speed) or 1
  local direction_sign = direction == "Left" and -1 or 1

  local time_phase = globals.realtime() * animation_speed * 0.22 * direction_sign

  for index = 1, length do
    local progress = (offset + index - 1) / denominator
    local hue = (progress + time_phase) % 1
    local h = hue * 6
    local c = sat
    local x = c * (1 - math.abs((h % 2) - 1))
    local m = 0.5 - c / 2
    local r, g, b

    if h < 1 then
      r, g, b = c, x, 0
    elseif h < 2 then
      r, g, b = x, c, 0
    elseif h < 3 then
      r, g, b = 0, c, x
    elseif h < 4 then
      r, g, b = 0, x, c
    elseif h < 5 then
      r, g, b = x, 0, c
    else
      r, g, b = c, 0, x
    end

    r = math.floor((r + m) * 255 + 0.5)
    g = math.floor((g + m) * 255 + 0.5)
    b = math.floor((b + m) * 255 + 0.5)

    out[#out + 1] = "\a" .. string.format("%02X%02X%02X%02X", r, g, b, alpha)
    out[#out + 1] = chars[index]
  end

  return table.concat(out)
end

local GAMESENSE_SETTINGS_VALUE = "\aFFFFFFFFGame\a96C83CFFSense\aFFFFFFFF settings\r"
local GAMESENSE_SETTINGS_GLYPH = "\238\139\189" -- U+E2FD
local GAMESENSE_SETTINGS_OPTION = "\a96C83CFF" .. GAMESENSE_SETTINGS_GLYPH .. "\r  " .. GAMESENSE_SETTINGS_VALUE
local MISCELLANEOUS_OPTION

do
  Class.util:sync_accent()
  Class.util:sync_macros()
  MISCELLANEOUS_OPTION = string.format("%s  \aA0A0A0FFMiscellaneous\r", pui.macros.misc)
  MENU_ROUTES = {
    page_home = string.format("%s  \aA0A0A0FFHome\r", pui.macros.home),
    page_antiaim = string.format("%s  \aA0A0A0FFAnti-Aim\r", pui.macros.antiaim),
    page_visuals = string.format("%s  \aA0A0A0FFVisuals\r", pui.macros.visuals),
    page_misc = string.format("%s  \aA0A0A0FFMisc\r", pui.macros.misc),
    root_home = string.format("%s  \aA0A0A0FFmenu\r", pui.macros.home),
    root_config = string.format("%s  \aA0A0A0FFconfig\r", pui.macros.config),
    legacy_root_ragebot = string.format("%s  \aA0A0A0FFragebot\r", pui.macros.ragebot),
    root_antiaim = string.format("%s  \aA0A0A0FFanti-aimbot\r", pui.macros.antiaim),
    root_visuals = string.format("%s  \aA0A0A0FFvisuals\r", pui.macros.visuals),
    root_misc = string.format("%s  \aA0A0A0FFMiscellaneous\r", pui.macros.misc),
    aa_builder = string.format("%s  \aA0A0A0FFBuilder\r", pui.macros.antiaim_builder),
    aa_additional = string.format("%s  \aA0A0A0FFAdditional\r", pui.macros.antiaim_additional),
    visuals_interface = string.format("%s  \aA0A0A0FFInterface\r", pui.macros.visuals_interface),
    visuals_other = string.format("%s  \aA0A0A0FFOther\r", pui.macros.visuals_other),
  }
  Class.ui.antiaim_conditions_t = {}
  Class.ui.antiaim_conditions_ct = {}
  local antiaim_conditions = {"Shared", "Standing", "Running", "Slowing", "Air", "Air Crouching", "Crouching", "Sneaking", "Freestanding", "Legit AA"}
  local antiaim_condition_states = {"Standing", "Running", "Slowing", "Air", "Air Crouching", "Crouching", "Sneaking"}
  local antiaim_condition_options = {}
  Class.ui._builder_action_rows = {}
for index = 1, #antiaim_conditions do
    antiaim_condition_options[index] = pui.macros.dot_accent .. "   " .. string.format("\aBDBDBDFF%s\r", antiaim_conditions[index])
  end
  local antiaim_team_states = {
   pui.macros.dot_accent .. "   " .. "\aE8B060FFTerrorist\r",
   pui.macros.dot_accent .. "   " .. "\a7AA2D4FFCounter-Terrorist\r"
  }

  -- Custom tab columns (Skeet LUA A/B sources → page-specific Core / Panel / Side)
  local main_group = pui.group("lua", "a")
  local fakelag_group = pui.group("lua", "b")

  -- Create native tab BEFORE controls so adopt_remaining can capture them
  local _ag_tab = nil
  do
    local ok_req, custom_tab = pcall(require, "lib/custom_tab")
    if ok_req and custom_tab then
local ICON_PNG = table.concat({
    "\137\080\078\071\013\010\026\010\000\000\000\013\073\072\068\082\000\000\000\064\000\000\000\064",
    "\008\006\000\000\000\170\105\113\222\000\000\018\114\073\068\065\084\120\156\229\155\233\143\028",
    "\199\121\198\127\085\213\199\092\061\179\187\036\247\036\105\138\020\116\004\166\067\089\178\197",
    "\036\016\044\031\081\000\009\142\100\056\134\236\216\240\007\125\112\140\000\070\128\252\033\001",
    "\130\000\070\002\004\006\098\072\112\162\040\144\101\091\142\079\073\150\097\091\118\024\075\150",
    "\018\081\146\117\153\220\037\185\203\229\206\206\061\125\084\085\062\244\177\051\123\105\073\173",
    "\140\000\124\009\098\186\123\118\186\235\121\234\173\183\222\171\225\058\023\241\251\122\144\020",
    "\082\073\169\060\041\164\015\120\128\003\200\236\107\003\036\064\100\172\009\141\209\145\177\070",
    "\255\062\198\245\158\017\032\133\116\165\084\021\037\100\003\168\075\169\130\170\087\155\150\082",
    "\029\000\234\064\025\112\179\063\143\129\001\208\054\070\095\233\069\221\021\099\116\007\104\107",
    "\107\090\198\232\190\177\038\126\047\198\185\175\004\072\033\029\041\085\085\009\057\041\165\058",
    "\084\245\106\183\072\169\110\018\112\076\010\121\068\073\085\147\066\149\217\085\003\244\064\027",
    "\221\053\214\156\183\240\182\049\250\181\094\212\125\197\024\125\089\091\211\052\070\247\140\053",
    "\201\126\141\121\095\008\200\102\187\238\042\119\166\234\213\110\149\082\221\161\132\060\165\164",
    "\090\144\066\077\010\081\204\184\035\016\187\062\211\098\045\041\025\003\107\105\027\171\155\218",
    "\232\037\109\205\011\198\232\051\189\168\123\054\214\241\178\049\186\189\031\090\241\174\008\200",
    "\214\117\224\042\119\174\234\213\062\232\042\247\163\082\170\219\148\080\179\066\208\000\202\002",
    "\033\183\060\072\128\216\244\104\139\005\059\122\094\092\055\164\100\180\180\213\151\140\209\207",
    "\199\058\126\186\023\117\127\029\235\248\162\049\186\243\110\236\197\053\019\032\133\044\187\202",
    "\157\009\074\141\147\174\114\239\083\082\157\150\066\045\008\065\093\032\188\252\230\098\100\194",
    "\247\250\048\059\122\108\237\040\025\081\166\021\075\218\232\231\098\029\063\217\025\182\094\138",
    "\117\188\108\172\025\092\011\142\171\038\064\010\041\179\089\063\018\148\026\159\116\149\251\041",
    "\037\212\081\033\152\016\008\095\100\119\021\035\115\156\031\237\174\252\027\098\051\196\057\116",
    "\203\134\134\100\199\161\181\172\107\171\207\197\058\126\188\051\108\125\059\214\241\249\076\027",
    "\204\213\224\185\042\002\164\144\142\171\220\003\065\169\113\171\171\220\207\043\169\238\086\082",
    "\205\009\068\117\051\112\145\158\108\037\225\029\158\049\050\219\027\231\054\061\223\134\136\158",
    "\054\250\162\054\250\153\088\199\143\116\134\173\179\177\142\175\092\141\145\220\051\001\082\072",
    "\207\085\238\076\163\050\117\218\085\238\067\074\168\015\008\193\065\129\240\114\085\207\129\231",
    "\051\061\166\005\123\088\010\155\085\063\191\086\144\049\074\132\045\008\137\172\101\085\091\253",
    "\098\172\227\175\181\250\107\207\101\075\034\218\011\174\061\017\144\129\159\107\084\166\062\230",
    "\042\247\203\074\168\027\165\016\013\001\106\055\224\057\232\205\090\176\233\099\003\248\054\170",
    "\159\147\177\029\017\019\245\122\254\157\190\210\106\181\180\213\175\199\058\254\199\086\127\237",
    "\169\088\199\023\247\066\130\179\007\240\078\054\243\031\115\149\251\021\071\170\019\002\017\008",
    "\016\155\193\143\002\031\005\157\019\227\057\014\158\114\241\156\157\031\027\037\049\081\146\016",
    "\233\164\000\042\132\200\102\061\035\069\088\038\131\006\055\028\062\204\199\239\060\205\163\063",
    "\248\190\106\182\219\147\066\168\091\128\175\052\042\083\180\250\107\063\202\072\216\117\057\236",
    "\074\128\020\082\186\202\061\144\169\253\151\051\240\245\081\144\082\136\093\129\123\142\139\239",
    "\056\120\202\193\117\028\014\079\029\220\153\000\011\145\078\088\092\091\077\073\072\018\162\036",
    "\038\076\018\216\068\196\084\189\193\151\062\253\025\038\130\058\255\253\242\203\052\219\045\177",
    "\214\110\215\029\169\078\000\095\110\084\166\186\173\254\218\179\177\142\047\239\102\024\119\039",
    "\064\170\032\051\120\015\041\161\110\204\102\030\033\004\178\000\060\014\062\007\238\059\233\076",
    "\087\253\018\071\166\014\226\058\014\174\082\072\033\113\149\218\009\063\190\214\220\060\187\064",
    "\108\052\081\146\146\209\029\014\169\084\202\084\042\021\026\065\128\005\110\088\088\224\248\194",
    "\017\038\234\117\190\244\233\207\000\176\214\110\177\214\110\005\087\090\173\027\087\091\205\135",
    "\130\082\227\242\250\160\057\052\218\180\118\194\184\163\013\144\066\150\125\183\116\098\162\060",
    "\249\055\174\242\238\149\066\204\228\107\126\059\240\249\053\207\113\240\029\183\000\094\241\253",
    "\002\180\181\150\068\107\140\181\059\061\022\033\004\142\082\072\033\136\181\070\091\067\063\012",
    "\233\198\017\247\220\117\023\243\051\051\084\042\021\110\056\124\152\137\160\206\100\189\078\179",
    "\221\230\205\197\243\188\185\180\200\027\139\231\121\244\007\223\211\087\090\173\229\088\071\223",
    "\093\031\052\255\062\140\135\111\236\228\039\108\171\001\082\072\149\057\057\159\084\082\221\157",
    "\090\251\017\131\055\002\190\088\002\035\179\126\098\122\142\138\231\227\187\046\100\160\227\036",
    "\198\090\010\002\148\148\099\086\048\049\154\068\027\180\053\040\041\211\103\008\129\146\018\037",
    "\037\135\015\028\228\119\111\255\142\183\151\150\248\252\159\223\207\100\080\103\162\094\031\035",
    "\238\199\191\252\005\111\044\158\039\029\043\007\149\084\119\007\165\198\155\198\232\111\196\058",
    "\062\191\157\199\184\061\001\169\234\159\116\149\251\169\108\159\247\182\091\243\155\193\215\252",
    "\018\199\167\231\232\014\251\212\252\018\137\214\068\113\076\171\223\163\094\174\096\177\172\247",
    "\186\084\252\018\042\245\144\073\140\065\027\195\048\137\089\237\118\072\140\217\216\061\050\231",
    "\194\119\028\102\194\033\237\243\125\142\207\205\243\232\147\223\225\075\159\251\092\065\192\122",
    "\187\205\063\255\199\191\243\235\151\095\102\173\221\194\002\002\225\041\169\230\092\248\084\080",
    "\106\252\207\250\160\185\110\180\089\127\071\002\164\144\174\171\220\057\087\185\247\041\161\142",
    "\230\078\078\177\190\217\164\005\155\192\075\041\152\170\006\068\073\066\187\223\163\236\251\084",
    "\075\037\194\036\198\090\203\193\201\041\074\165\050\245\160\070\171\211\097\173\213\226\220\242",
    "\101\134\073\076\162\013\201\054\110\189\167\028\154\253\030\053\191\196\106\107\157\099\011\011",
    "\244\122\253\226\251\102\167\205\122\187\077\171\211\201\070\103\115\183\171\170\132\058\234\042",
    "\247\062\087\185\175\103\145\228\088\000\181\149\000\169\234\085\175\246\065\037\213\233\212\189",
    "\029\007\059\190\230\199\193\043\041\104\246\186\076\084\170\104\163\041\121\030\198\024\140\133",
    "\082\185\068\165\090\101\126\102\134\211\119\222\073\098\012\231\046\044\241\245\199\031\167\027",
    "\014\073\118\241\096\035\157\238\100\093\059\164\027\199\148\074\101\060\199\097\105\249\082\010",
    "\019\152\108\052\152\172\215\089\107\183\192\102\091\175\181\008\193\132\146\234\116\213\171\253",
    "\052\214\241\138\209\230\202\142\004\228\123\190\171\220\143\074\161\022\004\194\167\000\157\091",
    "\248\013\013\216\012\126\165\181\206\129\090\157\040\073\232\014\250\248\142\135\182\134\082\169",
    "\068\057\008\120\224\222\123\153\155\157\037\049\134\181\214\058\223\255\217\207\008\147\120\087",
    "\240\155\137\112\125\143\099\199\143\209\108\183\249\249\127\157\097\165\213\228\158\187\238\226",
    "\227\119\158\230\173\197\069\154\237\054\008\139\176\096\005\008\043\124\041\212\130\171\220\143",
    "\186\202\125\222\024\221\026\245\013\198\009\144\170\154\197\243\183\165\081\029\035\074\159\047",
    "\131\244\154\231\056\120\142\083\168\125\179\215\229\064\173\142\054\026\173\053\142\084\012\162",
    "\016\233\058\084\235\001\127\249\023\159\102\110\102\022\011\156\187\176\196\087\031\126\152\115",
    "\023\150\104\117\058\123\002\095\144\144\104\086\154\077\190\253\244\211\036\131\033\101\215\229",
    "\225\111\061\193\159\220\126\123\049\062\091\140\027\082\255\129\186\148\234\182\170\087\187\053",
    "\214\241\210\232\182\056\182\013\250\142\127\172\081\153\250\171\146\083\250\162\020\098\094\008",
    "\144\136\194\216\201\017\067\024\148\202\156\152\158\035\140\035\166\170\001\073\182\111\107\173",
    "\105\247\251\169\149\087\146\153\233\105\190\248\224\103\089\152\155\123\215\224\001\038\051\195",
    "\231\042\135\126\191\079\189\092\226\248\220\060\231\175\092\166\051\028\176\214\110\099\108\026",
    "\049\024\107\049\089\138\197\088\123\097\152\012\191\222\234\175\253\083\152\132\111\231\247\043",
    "\052\032\203\234\028\082\066\158\202\146\025\059\206\126\190\207\087\060\159\154\095\074\129\027",
    "\077\119\208\199\145\010\037\037\090\192\252\244\012\095\124\240\065\022\230\230\168\007\001\231",
    "\046\092\224\145\039\158\184\102\240\064\170\226\035\226\057\014\189\126\159\056\140\233\247\007",
    "\219\106\065\234\078\211\080\066\158\146\082\029\146\066\046\229\198\048\207\201\033\165\170\084",
    "\189\218\045\074\170\005\160\156\223\136\145\181\015\100\238\173\195\145\169\131\248\174\139\016",
    "\130\118\191\135\054\006\223\241\136\146\004\148\100\126\118\110\012\252\048\012\089\111\183\025",
    "\134\067\044\022\223\243\174\137\128\205\146\146\111\153\105\076\020\046\118\110\180\011\251\149",
    "\254\105\089\073\181\144\229\041\043\005\238\252\064\009\217\144\082\221\036\133\154\020\008\057",
    "\026\201\141\250\247\094\062\251\190\015\214\018\197\049\101\223\199\090\139\182\134\238\112\064",
    "\185\082\225\129\123\239\029\007\223\105\115\246\205\215\057\113\236\125\220\254\254\247\211\008",
    "\130\125\033\033\074\018\150\219\045\092\199\161\230\151\241\029\119\235\184\083\066\164\020\106",
    "\082\074\117\083\150\169\030\039\000\168\011\056\150\037\048\011\192\027\199\249\182\151\206\190",
    "\020\146\196\024\090\253\030\082\136\052\144\137\099\202\149\050\243\051\179\028\158\159\031\003",
    "\255\203\223\060\207\048\026\226\123\046\211\007\015\114\251\201\253\033\033\210\105\192\100\140",
    "\225\240\129\052\208\026\053\108\099\024\082\195\126\012\054\048\074\216\072\110\074\033\143\144",
    "\169\255\232\013\070\147\025\121\084\151\250\246\134\122\185\146\122\124\058\161\059\028\080\171",
    "\214\248\196\221\031\033\168\213\198\192\175\119\218\132\097\132\064\080\242\124\038\130\128\059",
    "\078\158\220\031\018\146\164\200\029\108\089\006\005\014\000\202\082\200\035\025\086\181\065\128",
    "\084\094\213\171\077\043\169\106\100\134\049\159\241\081\034\060\103\020\188\221\200\208\088\139",
    "\214\026\099\013\181\106\149\122\045\072\103\063\010\121\225\236\203\035\224\211\251\072\160\228",
    "\167\036\156\188\249\102\074\190\255\174\008\136\019\205\226\218\021\176\233\238\224\057\110\241",
    "\093\238\188\101\226\040\169\106\089\129\198\219\032\064\072\095\074\117\064\010\085\222\156\183",
    "\031\061\241\148\203\225\092\253\181\038\209\154\245\094\023\109\012\198\140\131\007\024\134\033",
    "\097\020\018\134\225\088\168\156\027\214\146\239\083\242\061\074\251\177\012\116\130\177\134\035",
    "\083\135\054\180\096\211\223\009\132\144\066\149\083\172\210\047\008\032\173\212\212\179\207\045",
    "\191\204\119\131\220\249\113\149\074\247\088\107\169\248\037\226\036\161\051\028\080\029\081\255",
    "\173\119\216\154\044\201\189\203\157\131\242\171\016\075\170\157\142\218\098\007\054\097\026\195",
    "\154\019\224\144\085\110\242\001\238\069\148\148\069\084\183\157\006\140\062\123\124\075\029\013",
    "\174\198\071\247\094\201\008\166\049\172\057\001\146\180\080\041\183\252\178\184\193\094\047\110",
    "\072\170\226\254\014\107\092\016\134\033\097\020\049\012\195\221\111\116\149\242\014\195\026\195",
    "\186\035\224\253\144\146\231\115\234\150\063\096\034\168\111\033\033\221\033\058\252\230\213\087",
    "\009\163\061\101\176\223\019\025\173\206\198\217\231\182\178\109\018\107\231\204\022\144\091\250",
    "\058\119\254\225\109\052\130\058\037\047\037\097\024\070\180\058\029\126\245\210\075\180\058\157",
    "\119\173\001\174\082\197\255\061\012\107\012\107\078\064\066\090\159\079\210\027\188\195\045\182",
    "\145\157\126\081\242\125\026\065\157\091\142\159\096\024\069\044\095\089\101\121\117\149\095\189",
    "\244\034\173\078\123\095\212\223\085\138\185\198\196\142\201\214\116\124\197\008\199\176\230\193",
    "\080\004\180\179\207\060\146\024\249\049\136\141\154\085\113\043\109\210\028\158\037\053\136\221",
    "\094\151\118\183\067\187\211\041\012\161\005\074\190\007\002\126\251\246\239\120\237\173\055\009",
    "\163\136\048\012\025\238\147\234\187\202\193\081\014\174\084\012\137\199\198\056\006\098\027\172",
    "\018\032\107\075\185\098\172\030\088\198\083\182\163\039\081\018\019\233\132\068\235\034\105\217",
    "\011\135\120\142\067\173\084\166\219\235\241\163\103\126\066\167\219\221\050\200\146\231\035\128",
    "\048\074\213\127\255\192\043\130\090\141\122\080\067\122\046\113\086\084\217\060\246\244\220\090",
    "\099\245\032\197\106\194\013\002\140\142\122\081\119\069\027\221\165\088\006\140\081\097\177\069",
    "\158\222\243\060\130\074\149\160\082\097\162\090\043\050\183\221\110\175\208\128\241\007\067\035",
    "\008\184\239\099\031\167\017\212\217\079\113\149\195\013\179\115\124\224\212\041\092\223\231\252",
    "\218\042\081\178\145\246\179\227\218\144\104\163\187\089\011\206\152\006\232\172\180\124\030\024",
    "\140\021\041\051\087\023\242\192\035\193\113\028\078\222\120\051\149\082\185\136\021\084\150\007",
    "\232\246\186\180\059\091\073\168\007\001\071\231\231\057\058\063\079\099\147\159\112\045\018\212",
    "\106\204\207\206\114\243\141\055\114\252\134\027\056\114\244\008\051\243\243\052\038\039\240\075",
    "\165\172\102\184\129\036\059\026\024\107\206\143\054\085\140\166\196\218\022\222\182\150\118\030",
    "\017\090\044\002\065\189\090\101\162\026\048\081\173\081\043\149\121\223\236\060\243\211\051\052",
    "\059\109\250\113\132\002\218\189\030\081\018\211\237\246\248\225\079\158\041\162\193\081\105\004",
    "\001\159\191\255\126\190\250\112\231\093\037\069\032\085\253\123\062\114\055\199\022\022\056\116",
    "\040\117\127\079\220\122\011\177\163\120\236\201\111\141\000\031\033\193\166\024\073\109\000\099",
    "\004\100\221\088\175\025\171\155\066\168\121\107\145\069\045\014\184\231\142\211\028\061\052\203",
    "\161\198\004\245\074\021\215\113\056\125\242\020\055\044\028\102\165\217\228\103\047\156\193\115",
    "\028\214\186\029\046\094\186\196\226\133\011\217\218\220\032\161\017\004\028\157\095\224\175\191",
    "\240\133\119\149\022\115\178\045\175\185\188\194\135\078\157\226\208\161\067\000\116\195\144\151",
    "\094\061\155\001\223\092\093\182\198\088\221\052\070\191\166\237\070\078\176\112\132\140\209\253",
    "\094\212\125\069\027\189\068\182\012\138\230\004\011\191\120\249\069\234\149\042\211\147\083\076",
    "\079\030\096\178\222\160\094\173\082\175\214\120\225\183\103\033\091\006\181\082\153\254\096\192",
    "\227\223\125\146\165\139\023\183\044\133\081\018\142\206\047\092\245\114\016\128\167\020\117\199",
    "\099\109\189\073\171\217\100\117\117\149\213\213\085\046\092\186\072\039\179\065\227\141\020\000",
    "\012\180\209\075\089\199\089\081\084\216\032\192\154\056\107\069\123\193\090\090\041\246\244\095",
    "\187\223\229\220\229\101\030\125\246\135\180\122\153\133\183\169\218\255\252\197\231\137\227\056",
    "\117\105\147\008\215\113\016\218\112\225\210\069\254\229\223\254\149\197\125\036\193\145\146\146",
    "\235\049\081\170\080\245\125\170\202\225\202\234\021\126\250\244\051\060\246\205\199\051\002\186",
    "\099\093\038\035\061\005\173\172\211\236\242\104\113\100\204\021\206\250\240\206\104\171\047\089",
    "\108\084\048\152\209\104\045\180\251\061\022\047\047\179\120\121\153\086\175\199\122\191\135\146",
    "\018\071\041\106\165\010\174\114\072\140\198\177\130\229\149\021\190\190\007\018\078\222\124\203",
    "\174\198\209\145\138\146\155\214\032\142\076\078\113\048\008\040\185\046\073\020\243\212\051\079",
    "\243\214\219\111\241\202\235\191\229\219\223\251\207\098\246\011\235\159\230\044\162\172\195\236",
    "\140\182\166\057\122\239\177\184\065\010\233\248\110\233\166\137\242\228\223\186\202\187\095\010",
    "\113\048\079\141\191\111\122\150\007\063\242\167\052\170\053\126\112\230\057\004\240\103\031\250",
    "\099\036\112\230\127\095\228\213\197\115\069\118\072\107\077\156\237\024\210\081\105\106\252\179",
    "\159\101\126\102\118\139\097\108\117\058\180\058\169\081\252\206\083\079\209\234\116\104\119\059",
    "\244\186\061\186\189\094\086\040\133\067\181\058\101\215\195\119\093\092\165\104\015\251\076\086",
    "\107\104\107\120\229\194\034\097\214\071\176\067\074\124\053\214\209\019\235\131\230\223\133\241",
    "\240\181\029\011\035\198\154\036\214\241\114\172\227\167\149\084\119\008\161\002\097\133\111\069",
    "\058\251\173\126\143\239\159\249\005\139\151\087\144\089\054\248\019\183\125\024\099\045\147\213",
    "\026\043\237\180\050\004\208\143\067\202\158\135\054\134\094\167\195\055\030\123\140\007\238\189",
    "\143\185\217\089\106\213\042\181\106\181\208\132\070\144\134\208\083\141\006\075\023\047\113\113",
    "\249\018\063\126\246\089\002\229\224\040\133\163\036\097\156\080\242\092\028\169\184\210\109\051",
    "\221\152\064\091\203\027\043\151\010\240\249\214\183\105\246\067\099\245\082\172\227\167\179\222",
    "\161\177\142\145\045\145\163\020\210\245\221\210\141\089\095\192\003\089\095\000\019\213\000\153",
    "\197\243\157\126\015\033\004\019\213\090\081\030\059\084\011\144\066\022\181\193\068\107\180\209",
    "\153\051\101\041\149\203\084\043\021\230\102\103\249\163\059\239\164\154\017\144\139\005\122\189",
    "\030\207\061\247\075\046\044\095\162\223\235\051\024\166\037\253\188\076\238\040\197\122\191\151",
    "\205\188\229\205\149\139\116\135\067\134\089\225\213\194\152\006\100\231\203\177\142\190\153\245",
    "\009\188\254\142\197\081\099\077\028\235\248\098\172\227\039\165\084\031\020\066\213\064\084\091",
    "\253\110\081\021\018\164\042\209\234\117\017\008\218\174\067\187\223\227\248\244\044\019\213\026",
    "\142\148\041\160\112\072\217\243\144\066\049\028\012\025\012\006\012\006\003\046\092\186\180\101",
    "\041\096\161\221\237\048\028\012\232\245\250\008\145\110\119\198\090\006\081\072\163\082\197\081",
    "\106\011\248\112\004\188\029\049\123\069\027\093\218\075\248\100\214\047\180\165\181\118\219\220",
    "\065\214\032\113\164\081\153\250\156\167\220\135\148\084\071\229\059\244\008\248\110\218\014\115",
    "\098\122\142\238\112\192\129\090\029\065\154\177\109\245\123\004\229\050\214\194\122\175\075\213",
    "\247\145\114\107\042\066\027\067\047\012\153\172\214\064\064\103\208\167\081\169\102\073\078\203",
    "\106\167\077\173\092\230\141\149\075\244\050\240\102\004\124\113\156\174\255\072\027\125\046\074",
    "\091\231\118\108\144\216\049\121\114\045\045\050\121\067\212\137\233\057\042\190\143\239\122\069",
    "\135\136\201\182\146\056\059\118\054\017\096\051\002\164\016\056\082\021\193\150\163\020\066\192",
    "\048\138\233\071\195\109\214\252\134\187\110\040\090\234\116\166\250\215\214\034\003\096\172\025",
    "\196\058\062\031\235\248\017\041\213\097\080\031\150\066\076\098\173\048\066\032\173\221\072\244",
    "\089\139\017\130\048\011\066\094\095\185\072\205\047\115\228\192\065\042\158\143\051\146\072\117",
    "\117\130\053\155\226\237\140\002\075\170\081\142\114\144\082\016\235\180\236\213\031\014\057\191",
    "\182\074\047\028\238\005\188\053\214\182\178\198\201\071\178\153\223\177\143\120\215\046\049\099",
    "\116\167\051\108\157\149\082\125\013\197\084\218\135\039\234\057\096\097\045\114\132\004\050\018",
    "\194\172\215\175\027\014\168\249\229\180\098\163\020\142\114\080\082\224\121\238\246\015\180\169",
    "\134\068\058\033\142\018\226\036\025\003\158\023\064\236\014\106\159\093\235\100\013\147\095\235",
    "\012\091\103\179\023\047\118\148\119\076\199\102\077\019\115\141\202\212\039\174\165\081\050\111",
    "\156\074\211\233\014\071\166\014\225\058\059\103\110\114\208\177\078\008\179\062\193\237\128\111",
    "\211\054\107\045\182\147\024\253\070\172\227\127\216\107\163\228\158\242\209\251\213\042\235\141",
    "\144\049\122\125\180\085\054\175\245\141\150\187\118\106\149\029\001\175\051\181\191\234\086\217",
    "\061\039\228\175\235\102\233\092\174\235\118\249\092\174\235\023\038\070\229\186\125\101\102\084",
    "\174\235\151\166\070\229\186\125\109\110\179\092\183\047\078\110\039\215\229\171\179\187\201\255",
    "\215\151\167\175\123\249\063\025\107\171\078\179\173\106\128\000\000\000\000\073\069\078\068\174",
    "\066\096\130",
})

      local function write_icon()
        for _, paths in ipairs({ "afterglow_tab_icon.png", "csgo/afterglow_tab_icon.png" }) do
          local ok = pcall(function()
            local f = io.open(paths, "wb")
            if not f then error("fail") end
            f:write(ICON_PNG)
            f:close()
          end)
          if ok then return paths end
        end
      end
      local icon_path = write_icon()
      local opts = {
        position = "after_lua",
        replace_existing = true,
        -- Leave native menu dimensions untouched during tab insertion.
        categories = {
          -- Each independently switching right-side section owns a native card.
          { name = "Navigate",              grid = custom_tab.pack_grid(12, 0,  12, 4) },
          { name = "Core",                  grid = custom_tab.pack_grid(0,  0,  12, 16) },
          { name = "Panel",                 grid = custom_tab.pack_grid(12, 4,  12, 13) },
          { name = "States",                grid = custom_tab.pack_grid(12, 17, 12, 7) },
          { name = "Manipulations & Info",  grid = custom_tab.pack_grid(12, 10, 12, 6) },
          { name = "Notifications",         grid = custom_tab.pack_grid(12, 17, 12, 7) },
          { name = "Thankfulness",          grid = custom_tab.pack_grid(12, 17, 12, 7) },
          { name = "Improvements",          grid = custom_tab.pack_grid(12, 17, 12, 7) },
          { name = "Network",               grid = custom_tab.pack_grid(12, 16, 12, 8) },
          { name = "Defensive AA",           grid = custom_tab.pack_grid(0, 16, 12, 8) },
          { name = "Exploits",               grid = custom_tab.pack_grid(12, 17, 12, 7) },
        },
      }
      if icon_path then opts.icon, opts.icon_path = icon_path, icon_path
      else opts.icon_data = ICON_PNG end

      local ok_tab, tab = pcall(function() return custom_tab.create(opts) end)
      if not ok_tab then
        opts.icon, opts.icon_path, opts.icon_data = nil, nil, ICON_PNG
        ok_tab, tab = pcall(function() return custom_tab.create(opts) end)
      end
      if ok_tab then
        _ag_tab = tab
        Class.ui._ag_tab = tab
      end
    end
  end

  function Class.ui.print_watermark_guide()
    local red, purple, white = "FF4B5C", "9B5CFF", "E1E1E1"
    local lines = {
     {{color=red,text="[ afterglow ]"}, {color=purple,text=" WATERMARK"}},
     {{color=white,text="Plain text is supported, as are inline Heroicons names separated by spaces."}},
     {{color=white,text="Parts: pre=prefix m=main text post=postfix."}},
     {{color=white,text="Main text icon: icon=sparkles (uses the main text color and effects)."}},
     {{color=white,text="Side icons: icon_pre=sparkles and icon_post=star (prefix/postfix colors)."}},
     {{color=white,text="Example: pre=afterglow icon=sparkles m=.yaw post=[PRIVATE] icon_post=star"}},
     {{color=purple,text="Icons"}, {color=white,text=": https://heroicons.com/ — use supported names such as sparkles, star, heart."}},
     {{color=red,text="Colors"}, {color=white,text=": main, prefix and postfix can be colored separately; Gradient/Rainbow affect the main text."}}
    }
    for index = 1, #lines do
      Class.util:chat_print_colored(lines[index])
    end
  end
  local menu_was_open = false
  local menu_title_timer = 0
  local native_visibility_cache = {}
  local pui_visibility_cache = {}
  local page_selector_initialized = false

  local pui_visibility_patched = setmetatable({}, { __mode = "k" })
  local function patch_pui_visibility(control, visited)
    if type(control) ~= "table" then return end
    visited = visited or {}
    if visited[control] then return end
    visited[control] = true

    local original_set_visible = control.set_visible
    if type(original_set_visible) == "function" and not pui_visibility_patched[control] then
      local reference = control.reference or control.ref
      if reference ~= nil then
        local wrapped_set_visible = function(self, visible, ...)
          local result = original_set_visible(self, visible, ...)
          local native_reference = self.reference or self.ref
          if type(native_reference) == "table" then
            for _, item in pairs(native_reference) do
              if item ~= nil then pcall(ui.set_visible, item, visible and true or false) end
            end
          elseif native_reference ~= nil then
            pcall(ui.set_visible, native_reference, visible and true or false)
          end
          return result
        end
        local ok = pcall(function() control.set_visible = wrapped_set_visible end)
        if ok then pui_visibility_patched[control] = true end
      end
    end

    for key, value in pairs(control) do
      if key ~= "reference" and key ~= "ref" and type(value) == "table" then
        patch_pui_visibility(value, visited)
      end
    end
  end

  local function set_references_visible(cache_key, references, visible)
    visible = visible and true or false
    if native_visibility_cache[cache_key] == visible then return end
    native_visibility_cache[cache_key] = visible
    if not references then return end
    if type(references) == "table" then
      for _, reference in pairs(references) do
        if reference then pcall(ui.set_visible, reference, visible) end
      end
    else
      pcall(ui.set_visible, references, visible)
    end
  end

  local function set_pui_visible(cache_key, control, visible)
    visible = visible and true or false
    if not control then return end
    if pui_visibility_cache[cache_key] ~= visible then
      local ok = pcall(function() control:set_visible(visible) end)
      if ok then pui_visibility_cache[cache_key] = visible end
    end
    -- PUI wrappers can leave the native reference's row in the category
    -- layout. Apply visibility to the underlying menu item as well.
    local reference = control.reference
    if reference then
      if type(reference) == "table" then
        for _, item in pairs(reference) do
          if item then pcall(ui.set_visible, item, visible) end
        end
      else
        pcall(ui.set_visible, reference, visible)
      end
    end
  end

  local function hide_tab_selectors()
    local element = Class.ui.menu.home_tab.selected_tab.default
    if element and element.set_visible then pcall(element.set_visible, element, false) end
    if element and element.reference then pcall(ui.set_visible, element.reference, false) end
  end

  local function update_native_aa_other_visibility()
    local refs = Class.util.reference
    if not refs then return end
    set_references_visible("aa_slow_walk", refs.aa_slow_walk, true)
    set_references_visible("aa_legs_movement", refs.aa_legs_movement, true)
    set_references_visible("aa_hideshots", refs.aa_hideshots, true)
    set_references_visible("aa_fake_peek", refs.aa_fake_peek, true)
  end

  local canonical_roots = {
    [MENU_ROUTES.root_home] = MENU_ROUTES.root_home,
    [MENU_ROUTES.root_config] = MENU_ROUTES.root_home,
    [MENU_ROUTES.legacy_root_ragebot] = MENU_ROUTES.root_misc,
    [MENU_ROUTES.root_antiaim] = MENU_ROUTES.root_antiaim,
    [MENU_ROUTES.root_visuals] = MENU_ROUTES.root_visuals,
    [MENU_ROUTES.root_misc] = MENU_ROUTES.root_misc,
  }
  local route_to_page = {
    [MENU_ROUTES.root_home] = MENU_ROUTES.page_home,
    [MENU_ROUTES.root_config] = MENU_ROUTES.page_home,
    [MENU_ROUTES.legacy_root_ragebot] = MENU_ROUTES.page_misc,
    [MENU_ROUTES.root_antiaim] = MENU_ROUTES.page_antiaim,
    [MENU_ROUTES.root_visuals] = MENU_ROUTES.page_visuals,
    [MENU_ROUTES.root_misc] = MENU_ROUTES.page_misc,
  }
  local native_fl_refs = {
    Class.util.reference.aa_fakelag_enabled,
    Class.util.reference.aa_fakelag_amount,
    Class.util.reference.aa_fakelag_limit,
    Class.util.reference.aa_fakelag_variance
  }
  local native_fl_visibility_keys = {
    "aa_fakelag_enabled", "aa_fakelag_amount", "aa_fakelag_limit", "aa_fakelag_variance"
  }
  local function show_native_fakelag_controls()
    for index, refs in ipairs(native_fl_refs) do
      set_references_visible(native_fl_visibility_keys[index], refs, true)
    end
  end

  function Class.ui.setup_menu()
    Class.util:sync_accent()
    Class.util:hide_menu(false)
    ui.set(Class.util.reference.aa_enabled, true)
    show_native_fakelag_controls()
    hide_tab_selectors()
  end
  function Class.ui.update_menu()
    Class.util:sync_accent()
    local menu_open = ui.is_menu_open()
    local home = Class.ui.menu.home_tab
    local home_route = MENU_ROUTES.root_home
    local selected_root = home.selected_tab.default:get() or home_route
    local normalized_root = canonical_roots[selected_root] or MENU_ROUTES.root_home
    if selected_root ~= normalized_root then
      home.selected_tab.default:set(normalized_root)
    end
    selected_root = normalized_root
    if Class.ui._sync_nav_tabs then pcall(Class.ui._sync_nav_tabs, selected_root) end
    do
      local tab = Class.ui._custom_tab or Class.ui._ag_tab
      if tab and tab.set_category_name then
        local core_name, panel_name = "Core", "Panel"
        if selected_root == MENU_ROUTES.root_home then
          core_name = "Overview"
        elseif selected_root == MENU_ROUTES.root_antiaim then
          core_name = home.selected_tab.antiaim:get() == MENU_ROUTES.aa_builder and "Angles" or "Additional"
        elseif selected_root == MENU_ROUTES.root_visuals then
          core_name = home.selected_tab.visuals:get() == MENU_ROUTES.visuals_interface and "Visuals Interface" or "Visuals Other"
        elseif selected_root == MENU_ROUTES.root_misc then
          core_name = home.selected_tab.miscellaneous:get() == "Miscellaneous" and "General" or "Skeet DLL Tweaks"
        end
        local is_home_root = selected_root == MENU_ROUTES.root_home
        local selected_aa_tab = selected_root == MENU_ROUTES.root_antiaim and home.selected_tab.antiaim:get() or nil
        local selected_visuals_tab = home.selected_tab.visuals:get()
        local selected_misc_tab = home.selected_tab.miscellaneous:get()
        local is_aa_builder = selected_root == MENU_ROUTES.root_antiaim and selected_aa_tab == MENU_ROUTES.aa_builder
        local is_aa_additional = selected_root == MENU_ROUTES.root_antiaim and selected_aa_tab == MENU_ROUTES.aa_additional
        local is_gamesense_settings = selected_root == MENU_ROUTES.root_misc
          and home.selected_tab.miscellaneous:get() == GAMESENSE_SETTINGS_VALUE
        local is_miscellaneous = selected_root == MENU_ROUTES.root_misc
          and home.selected_tab.miscellaneous:get() == "Miscellaneous"
        if is_home_root then
          panel_name = "Home"
        elseif selected_root == MENU_ROUTES.root_antiaim then
          panel_name = is_aa_builder and "Tickbase Manipulations" or "Hotkeys"
        elseif selected_root == MENU_ROUTES.root_visuals then
          panel_name = "Watermark"
        elseif selected_root == MENU_ROUTES.root_misc then
          panel_name = "Misc"
        end
        pcall(function() tab:set_category_name(2, core_name) end)
        pcall(function() tab:set_category_name(3, panel_name) end)

        -- These cards are separate native categories. Switching pages hides the
        -- old card and shows the new one in the same grid position, allowing
        -- Skeet to run its native category transition instead of renaming one
        -- shared Side card.
        pcall(function() tab:set_category_visible(2, true) end)
        pcall(function() tab:set_category_visible(3, true) end)
        pcall(function() tab:set_category_visible(4, is_aa_builder) end)       -- States
        pcall(function() tab:set_category_visible(5, is_home_root) end)        -- Home Manipulations
        pcall(function() tab:set_category_visible(6, selected_root == MENU_ROUTES.root_visuals) end) -- Notifications
        pcall(function() tab:set_category_visible(7, is_gamesense_settings) end) -- Thankfulness
        pcall(function() tab:set_category_visible(8, is_miscellaneous) end)    -- Improvements
        pcall(function() tab:set_category_visible(9, is_home_root) end)        -- Network
        pcall(function() tab:set_category_visible(10, is_aa_builder) end)    -- Defensive AA (builder only)
        pcall(function() tab:set_category_visible(11, is_aa_additional) end)   -- Exploits

        -- Credits: builder -> Defensive AA card (footer); other routes -> left Core block (footer_core).
        local footer_def = Class.ui.menu.footer
        local footer_core = Class.ui.menu.footer_core
        local function set_footer_visible(f, vis)
          if not f then return end
          pcall(function() if f.title then f.title:set_visible(vis) end end)
          pcall(function() if f.credits then f.credits:set_visible(vis) end end)
        end
        set_footer_visible(footer_core, not is_aa_builder)
        set_footer_visible(footer_def, is_aa_builder)
        Class.ui.menu.footer_active = is_aa_builder and footer_def or footer_core

        -- Always apply a complete deterministic layout instead of reading
        -- native positions back from the menu. Home Manipulations therefore
        -- keeps the same 12x6 footprint on every root, including while hidden.
        -- Every subtab can change the controls inside Categories 2/3 even when
        -- the grid geometry stays identical. Include all subtab values so the
        -- native tab layout is refreshed for Visuals and Misc as well as AA.
        local layout_key = table.concat({
          tostring(selected_root),
          tostring(selected_aa_tab or ""),
          tostring(selected_visuals_tab or ""),
          tostring(selected_misc_tab or ""),
        }, ":")
        if Class.ui._home_category_layout_root ~= layout_key then
          local layout_applied = pcall(function()
            local function pack_grid(x, y, width, height)
              return x + width * 0x100 + y * 0x10000 + height * 0x1000000
            end
            local layouts = {
              pack_grid(12, 0, 12, 4),   -- 1: Navigate
              pack_grid(0, 0, 12, 24),   -- 2: Core (left, full height; credits at its bottom)
              pack_grid(12, 4, 12, 13),  -- 3: active page panel
              pack_grid(12, 17, 12, 7),  -- 4: States
              pack_grid(12, 10, 12, 6),  -- 5: Home Manipulations
              pack_grid(12, 17, 12, 7), -- 6: Notifications
              pack_grid(12, 17, 12, 7), -- 7: Thankfulness
              pack_grid(12, 17, 12, 7), -- 8: Improvements
              pack_grid(12, 16, 12, 8), -- 9: Network
              pack_grid(0, 16, 12, 8),  -- 10: Defensive AA (builder only)
              pack_grid(12, 17, 12, 7), -- 11: Exploits
            }
            if is_aa_builder then
              -- Builder: split the left column into Angles (Core) + Defensive AA below it.
              layouts[2] = pack_grid(0, 0, 12, 16)
            end
            if is_home_root then
              layouts[3] = pack_grid(12, 4, 12, 6)
            elseif is_aa_additional then
              -- Keep Hotkeys above a separate, empty Exploits card in the right column.
              layouts[3] = pack_grid(12, 4, 12, 13)
              layouts[11] = pack_grid(12, 17, 12, 7)
            end
            tab:set_category_layouts(layouts)
            -- Reflow every card after PUI dependencies switch the visible rows.
            for category_index = 2, 11 do
              pcall(function() tab:reflow_category(category_index) end)
            end
          end)
          if layout_applied then
            Class.ui._home_category_layout_root = layout_key
          end
        end
      end
    end


    -- Fake Lag stays native to GameSense; the Lua does not replace or hide it.
    show_native_fakelag_controls()
    -- Native dependencies/layout refreshes can re-show AA controls. Enforce
    -- the hidden tab after those refreshes on every menu update.
    if Class.util.set_aa_tab_hidden then
      Class.util:set_aa_tab_hidden(true)
    end

    local wanted_page = route_to_page[selected_root] or MENU_ROUTES.page_home
    pcall(function()
      if home.page_selector:get() ~= wanted_page then home.page_selector:set(wanted_page) end
      if not page_selector_initialized then
        home.page_selector:set_visible(false)
        page_selector_initialized = true
      end
      pcall(function() home.page_selector:set_visible(false) end)
    end)
    local antiaim_open = selected_root == MENU_ROUTES.root_antiaim
    local visuals_open = selected_root == MENU_ROUTES.root_visuals
    -- sub tabs live in Navigate; keep Core copies hidden
    set_pui_visible("antiaim_subtab", home.selected_tab.antiaim, false)
    set_pui_visible("visuals_subtab", home.selected_tab.visuals, false)
    set_pui_visible("misc_subtab", home.selected_tab.miscellaneous, false)
    local antiaim_builder_open = antiaim_open
      and home.selected_tab.antiaim:get() == MENU_ROUTES.aa_builder
    local show_native_other = not menu_open
      or (not visuals_open and not antiaim_builder_open)
    if Class.util._show_native_other ~= show_native_other then
      Class.util._show_native_other = show_native_other
      Class.util:hide_menu(false)
      update_native_aa_other_visibility()
    end
    if not menu_open then
      menu_was_open = false
      return
    end
    if not menu_was_open then
      hide_tab_selectors()
      menu_was_open = true
    end
    local current_time = globals.realtime()
    if current_time - menu_title_timer > 0.08 then
      menu_title_timer = current_time
      do
        local f = Class.util.accent_color.first
        local username = tostring(user_database.username or "")
        username = username:gsub("[%c]", ""):gsub("^%s+", ""):gsub("%s+$", "")
        if username == "" then username = "user" end
        local br = Class.util:get_branch()
        local ver = Class.util:get_update_date()
        local elapsed = math.max(0, math.floor((globals.realtime() or 0) - session_start_time))
        local hours = math.floor(elapsed / 3600)
        local minutes = math.floor((elapsed % 3600) / 60)
        local seconds = elapsed % 60
        local session = string.format("%02d:%02d:%02d", hours, minutes, seconds)
        local greeting = "Welcome"
        username = tostring(username or ""):gsub("[%c]", ""):gsub("^%s+", ""):gsub("%s+$", "")
        local hitrate_percent = hitrate_shots > 0 and math.floor((hitrate_hits / hitrate_shots) * 100) or 0
        local hitrate_text = string.format("%d / %d (%d%%)", hitrate_shots, hitrate_hits, hitrate_percent)
        local gradient_username = username
        if username ~= "" then
          local gradient_ok, gradient_result = pcall(Class.render.gradient_text, username, 2.5, 2,
            f[1], f[2], f[3], 255,
            f[1] * 0.75, f[2] * 0.75, f[3] * 0.75, 255)
          if gradient_ok and type(gradient_result) == "string" and gradient_result ~= "" then
            gradient_username = gradient_result
          end
        end
        local gradient_branch = Class.render.gradient_text(br, 2.5, 2,
        f[1], f[2], f[3], 255,
        f[1] * 0.75, f[2] * 0.75, f[3] * 0.75, 255)
        local gradient_version = Class.render.gradient_text(ver, 2.5, 2,
        f[1], f[2], f[3], 255,
        f[1] * 0.75, f[2] * 0.75, f[3] * 0.75, 255)
        local gradient_session = Class.render.gradient_text(session, 2.5, 2,
        f[1], f[2], f[3], 255,
        f[1] * 0.75, f[2] * 0.75, f[3] * 0.75, 255)
        local gradient_hitrate = Class.render.gradient_text(hitrate_text, 2.5, 2,
        f[1], f[2], f[3], 255,
        f[1] * 0.75, f[2] * 0.75, f[3] * 0.75, 255)
        Class.ui.menu.home_tab.title:set(
        pui.macros.dot_accent .. "  " .. "\v\xEE\x85\x82\r  afterglow"
        )
        Class.ui.menu.home_tab.info.user:set(
        greeting .. ", " .. gradient_username
        )
        Class.ui.menu.home_tab.info.branch:set(
        "Your branch is " .. gradient_branch
        )
        Class.ui.menu.home_tab.info.hitrate:set(
        "Your Hitrate is " .. gradient_hitrate
        )
        Class.ui.menu.home_tab.info.version:set(
        "Version released from " .. gradient_version
        )
        Class.ui.menu.home_tab.info.session:set(
        "The session lasts " .. gradient_session
        )

      end
    end
  end

  -- Unique, visually empty labels prevent collisions between unnamed sliders.
  -- These are UI identifiers only; they are not used in any depend() calls.
  local hidden_slider_ids = {
    aspect_ratio_amount = "\n" .. string.rep("\226\128\139", 1),
    viewmodel_position_x = "\n" .. string.rep("\226\128\139", 3),
    viewmodel_position_y = "\n" .. string.rep("\226\128\139", 4),
    viewmodel_position_z = "\n" .. string.rep("\226\128\139", 5),
    viewmodel_fov = "\n" .. string.rep("\226\128\139", 6),
  }
  -- PUI serializes controls by their displayed labels in some builds. Reusing "\n"
  -- for multiple controls makes presets/autosave restore values into the wrong control.
  -- Give every visually blank control its own invisible label.
  local hidden_control_ids = {
    page_selector = "\n" .. string.rep("\226\128\139", 40),
    safe_head_conditions = "\n\226\129\163" .. string.rep("\226\128\139", 41),
    manual_arrows_color = "\n\226\129\162" .. string.rep("\226\128\139", 42),
    manual_arrows_body_color = "\n\226\129\163" .. string.rep("\226\128\139", 43),
    manual_arrows_style = "\n\226\129\164" .. string.rep("\226\128\139", 44),
    crosshair_indicator_mode = "\n" .. string.rep("\226\128\139", 46),
    -- These two controls use distinct zero-width markers, not only different
    -- counts of the same character. This keeps PUI identifiers separate even
    -- on builds that normalize repeated zero-width spaces.
    event_logger_triggers = "\n\226\129\160" .. string.rep("\226\128\139", 7),
    config_name = "\n" .. string.rep("\226\128\139", 48),
    aspect_ratio_preset = "\n\239\187\191" .. string.rep("\226\128\139", 9),
    misc_subtab = "\n" .. string.rep("\226\128\139", 50),
    warmup_triggers = "\n\226\128\143" .. string.rep("\226\128\139", 52),
    animation_breaker_triggers = "\n" .. string.rep("\226\128\139", 53),
  }

  Class.ui.menu = {
   home_tab = {
    page_selector = main_group:combobox(hidden_control_ids.page_selector, MENU_ROUTES.page_home, MENU_ROUTES.page_antiaim, MENU_ROUTES.page_visuals, MENU_ROUTES.page_misc),
   selected_tab = {
    default = main_group:combobox("\n default_tab",
    MENU_ROUTES.root_home,
    MENU_ROUTES.legacy_root_ragebot,
    MENU_ROUTES.root_antiaim,
    MENU_ROUTES.root_visuals,
    MENU_ROUTES.root_misc,
    MENU_ROUTES.root_config
    ),
    antiaim = main_group:combobox("\n antiaim_tab",
    MENU_ROUTES.aa_builder,
    MENU_ROUTES.aa_additional
    ),
    visuals = main_group:combobox("\n visuals_tab",
    MENU_ROUTES.visuals_interface,
    MENU_ROUTES.visuals_other
    ),
    miscellaneous = main_group:combobox(hidden_control_ids.misc_subtab, "Miscellaneous", GAMESENSE_SETTINGS_VALUE),
   },
  title = fakelag_group:label(pui.macros.dot_accent .. " \v\xEE\x85\x82\r afterglow"),
  info = {
   user = fakelag_group:label("Welcome, " .. user_database.username),
   branch = fakelag_group:label("Your branch is " .. user_database.branch),
   hitrate = fakelag_group:label("Your Hitrate is 0 / 0 (0%)"),
   version = fakelag_group:label(string.format("Version ~ \v%s\r", user_database.update_date)),
   session = fakelag_group:label("Session ~ \v00:00:00\r"),
  },
  network = {},
  },
  gamesense_settings = {
   accurate_quick_stop = {
    enabled = main_group:checkbox(pui.macros.dot .. " \aB4B465FFAccurate Quick Stop\r \a929292FF[MAY AFFECT VAR]\r"),
   },
   custom_quick_switch = {
    enabled = fakelag_group:checkbox(pui.macros.dot .. " Custom Quick Switch"),
   },
   force_shot = {
    enabled = fakelag_group:checkbox(pui.macros.dot .. " Force Shot"),
    -- Inline keybind: created right after the checkbox so the native "inline"
    -- hotkey placement puts the key box on the checkbox row itself.
    hotkey = ui.new_hotkey("LUA", "b", "Force Shot", true),
    work_in_air = fakelag_group:checkbox(pui.macros.dot .. " Force Shot In Air", true),
    hit_chance = fakelag_group:slider(pui.macros.dot_accent .. " Force Shot Hit Chance", 0, 100, 25, true, "%"),
    indicator = fakelag_group:checkbox(pui.macros.dot .. " Force Shot Indicator", true),
    indicator_color = fakelag_group:color_picker(pui.macros.dot_accent .. " Indicator Color", 235, 235, 235, 255),
   },
   hide_shots_fakelag_fix = {
    enabled = fakelag_group:checkbox(pui.macros.dot .. " Hide Shots Fakelag Limit Fix"),
   },
   shot_delay_fix = {
    enabled = main_group:checkbox(pui.macros.dot .. " \aB4B465FFShot Delay Fix\r"),
   },
   double_tap_stability_fix = {
    enabled = main_group:checkbox(pui.macros.dot .. " \aB4B465FFDouble Tap Stability Fix\r"),
   },
   double_tap_return_fix = {
    enabled = main_group:checkbox(pui.macros.dot .. " \aB4B465FFDouble Tap Return Fix\r"),
   },
   defensive_double_tap_on_peek = {
    enabled = fakelag_group:checkbox(pui.macros.dot .. " Defensive Double Tap on Incoming Peek"),
   },
   animation_flag_preservation = {
    enabled = main_group:checkbox(pui.macros.dot .. " \aB4B465FFPreserve Animation Flags\r", true),
   },
   air_autostop = {
    enabled = main_group:checkbox(pui.macros.dot .. " \aB4B465FFAir Autostop\r"),
   },
   scan_accuracy_optimization = {
    enabled = main_group:checkbox(pui.macros.dot .. " \aB4B465FFScan Accuracy Optimization\r"),
   },
   spread_autostop_fix = {
    enabled = main_group:checkbox(pui.macros.dot .. " \aB4B465FFSpread & Autostop Fix\r"),
   },
   backtrack_record_fix = {
    enabled = main_group:checkbox(pui.macros.dot .. " \aB4B465FFBacktrack Record Fix\r"),
    lag_records = main_group:checkbox(pui.macros.dot .. " \aB4B465FFLag Records\r"),
    extended_lag_records = main_group:checkbox(pui.macros.dot .. " \aB4B465FFExtended Lag Records\r"),
    record_gap = main_group:slider(pui.macros.dot_accent .. " \aB4B465FFRecord Gap\r", 1, 10, 3, true, "t"),
    extended_record_gap = main_group:slider(pui.macros.dot_accent .. " \aB4B465FFExtended Record Gap\r\226\128\139", 1, 20, 3, true, "t"),
   },
   fake_lag = {
    reset_fake_lag_on_shot = fakelag_group:checkbox(pui.macros.dot .. " Reset Fake Lag on Shot"),
    reset_delay_ticks = fakelag_group:slider(pui.macros.dot_accent .. " Reset Delay (Ticks)", 1, 32, 16, true, "t", 1),
   },

  },
  antiaim_tab = {
   builder = {
    select = {
    },
  },
  additional = {
   fakelag = {
    anti_bruteforce = {
     enabled = main_group:checkbox(pui.macros.dot .. " Anti-Bruteforce"),
     conditions = main_group:multiselect(pui.macros.dot_accent .. " Conditions", {"Standing", "Running", "Slowing", "Air", "Air Crouching", "Crouching", "Sneaking"}),
     notify = main_group:multiselect(pui.macros.dot_accent .. " Notify", {"Event Logger", "On Screen"}),
     timeout = main_group:slider(pui.macros.dot_accent .. " Timeout", 0, 10, 3, true, "s", 1, {[0] = "Infinite"}),
     mode = main_group:combobox(pui.macros.dot_accent .. " Bruteforce Mode", "Increasing", "Decreasing", "Meta"),
    },
  },
  hotkey = {
   freestanding = fakelag_group:hotkey(pui.macros.dot .. " Freestanding"),
   body_freestanding = fakelag_group:checkbox(pui.macros.dot .. " Body Freestanding"),
   freestanding_disablers = fakelag_group:multiselect(pui.macros.dot .. " Disablers", antiaim_condition_states),
   manual_forward = fakelag_group:hotkey(pui.macros.dot .. " Manual Forward"),
   manual_left = fakelag_group:hotkey(pui.macros.dot .. " Manual Left"),
   manual_right = fakelag_group:hotkey(pui.macros.dot .. " Manual Right"),
   prefer_manual = fakelag_group:checkbox(pui.macros.dot .. " Prefer Manual"),
   manual_mode = fakelag_group:combobox(pui.macros.dot .. " Manual Mode", "Builder", "Jitter", "Static"),
  },
  extra = {
   safe_head_enabled = main_group:checkbox(pui.macros.dot .. " Safe Head"),
   safe_head = {
    conditions = main_group:multiselect(hidden_control_ids.safe_head_conditions, {"Air Crouch", "Crouch", "Taser", "Knife", "Above enemy"}),
    height_difference = main_group:slider(pui.macros.dot_accent .. " Height Difference", -200, 200, 25, true, "u", 1),
   },
  fast_ladder_enabled = main_group:checkbox(pui.macros.dot .. " Fast Ladder"),
  fast_ladder_avoid = main_group:checkbox(pui.macros.dot .. " Avoid Flying"),
  avoid_backstab_enabled = main_group:checkbox(pui.macros.dot .. " Avoid Backstab"),
  avoid_backstab = {
   amount = main_group:slider(pui.macros.dot_accent .. " Backstab Distance", 0, 350, 0, true, "u", 1, {[0] = "Disabled"}),
  },
  warmup = {
   enabled = main_group:checkbox(pui.macros.dot .. " Warmup AA"),
   triggers = main_group:multiselect(hidden_control_ids.warmup_triggers, {"Warmup", "No Enemies"}),
   pitch = main_group:combobox(pui.macros.dot_accent .. " Pitch" .. string.rep("\226\128\139", 62), "Disabled", "Down", "Up"),
   yaw_mode = main_group:combobox(pui.macros.dot_accent .. " Yaw Mode" .. string.rep("\226\128\139", 63), "Spin", "Distortion"),
   range = main_group:slider(pui.macros.dot_accent .. " Range" .. string.rep("\226\128\139", 64), 1, 180, 180, true, "°"),
   speed = main_group:slider(pui.macros.dot_accent .. " Speed" .. string.rep("\226\128\139", 65), 1, 100, 10, true, "%"),
  },
  }
  }
  },
  visuals_tab = {
   interface = {
    velocity_indicator = {
     enabled = main_group:checkbox(pui.macros.dot .. " Velocity Indicator"),
     color = main_group:color_picker(pui.macros.dot_accent .. " Velocity Color", 200, 200, 200, 255)
    },
   manual_arrows = {
    enabled = main_group:checkbox(pui.macros.dot .. " Manual Arrows"),
    style = main_group:combobox(hidden_control_ids.manual_arrows_style, "Team Skeet", "Custom", "CS2", "Modern"),
    yaw_color = main_group:color_picker(hidden_control_ids.manual_arrows_color, 175, 255, 55, 255),
    body_color = main_group:color_picker(hidden_control_ids.manual_arrows_body_color, 56, 158, 252, 255),
    custom_color = main_group:color_picker("\n\226\128\141" .. string.rep("\226\128\139", 54), 175, 255, 55, 255),
    cs2_idle_color = main_group:color_picker("CS2 idle color", 255, 68, 78, 255),
    font = main_group:combobox(pui.macros.dot_accent .. " Symbol Font", "Default", "Pixel", "Bold", "Large"),
    offset = main_group:slider(pui.macros.dot_accent .. " Arrow Offset", 10, 200, 42, true, "px"),
    left = main_group:textbox(pui.macros.dot_accent .. " Left", "左"),
    right = main_group:textbox(pui.macros.dot_accent .. " Right", "右"),
    forward = main_group:textbox(pui.macros.dot_accent .. " Forward", "前"),
   },
   crosshair_indicator = {
    enabled = main_group:checkbox(pui.macros.dot .. " Crosshair Indicator"),
    mode = main_group:combobox(hidden_control_ids.crosshair_indicator_mode, "Default", "Japanese"),
    runes_color_mode = main_group:combobox(pui.macros.dot_accent .. " Indicator Color Mode", "Static", "Gradient"),
    options = main_group:multiselect(pui.macros.dot_accent .. " Options", {"Fade on Scope", "Slide on Scope"}),
    direction = main_group:combobox(pui.macros.dot_accent .. " Direction", "Left", "Right"),
    gap_y = main_group:slider(pui.macros.dot_accent .. " Crosshair Indicator Distance", 0, 80, 17, true, "px"),
    color = main_group:color_picker(pui.macros.dot_accent .. " Crosshair Color", 140, 110, 115, 255),
   },

  damage_indicator = {
   enabled = main_group:checkbox(pui.macros.dot .. " Damage Indicator"),
   only_if_active = main_group:checkbox(pui.macros.dot .. " Only During Override"),
   font = main_group:combobox(pui.macros.dot_accent .. " Indicator Font", "Default", "Small", "Bold"),
   inactive_color = main_group:color_picker(pui.macros.dot_accent .. " Default Color", 255, 255, 255, 160),
   active_color = main_group:color_picker(pui.macros.dot_accent .. " Override Color", 255, 255, 255, 255),
  },
  custom_scope = {
   enabled = main_group:checkbox(pui.macros.dot .. " Custom Scope Overlay"),
   color = main_group:color_picker(pui.macros.dot_accent .. " Scope Color", 255, 255, 255, 150),
   mode = main_group:combobox(pui.macros.dot_accent .. " Scope Mode", "Default", "Rotated"),
   offset = {
    length = main_group:slider(pui.macros.dot_accent .. " Length", 0, 500, 190, true, "px"),
    gap = main_group:slider(pui.macros.dot_accent .. " Gap", 0, 500, 15, true, "px"),
   },
  appear_speed = main_group:slider(pui.macros.dot_accent .. " Appear Speed", 1, 24, 8, true, "fr", 1),
  animate = main_group:checkbox(pui.macros.dot .. " Animate"),
  reversed = main_group:checkbox(pui.macros.dot .. " Reversed"),
  },

  notifications = nil,
  },
  other = {
  watermark = {
   font = fakelag_group:combobox(pui.macros.dot .. " Watermark Font", "Default", "Pixel", "Bold"),
   color_mode = fakelag_group:combobox(pui.macros.dot .. " Watermark Color Mode", "Default", "Gradient", "Rainbow"),
   effect = fakelag_group:combobox(pui.macros.dot .. " Effect", "Disabled", "Pulse", "Encoded"),
   pulse_speed = fakelag_group:slider(pui.macros.dot .. " Pulse Speed", 1, 100, 30, true, "%", 1),
   default = {
    color = fakelag_group:color_picker(pui.macros.dot .. " Main Color", 222, 206, 168, 255),
   },
   gradient = {
    color = {
     prefix = fakelag_group:color_picker(pui.macros.dot .. " Prefix Color", 198, 238, 98, 255),
     inner = fakelag_group:color_picker(pui.macros.dot .. " Inner Color", 81, 81, 81, 255),
     outer = fakelag_group:color_picker(pui.macros.dot .. " Outer Color", 255, 255, 255, 255),
     postfix = fakelag_group:color_picker(pui.macros.dot .. " Postfix Color", 238, 104, 104, 255),
    },
    speed = fakelag_group:slider(pui.macros.dot .. " Gradient Speed", 0, 100, 10, true, "%", 1),
    direction = fakelag_group:combobox(pui.macros.dot .. " Gradient Direction", "Right", "Left"),
   },
   rainbow = {
    speed = fakelag_group:slider(pui.macros.dot .. " Rainbow Speed", 0, 100, 10, true, "%", 1),
    saturation = fakelag_group:slider(pui.macros.dot .. " Rainbow Saturation", 0, 100, 100, true, "%", 1),
    direction = fakelag_group:combobox(pui.macros.dot .. " Rainbow Direction", "Right", "Left"),
   },
   text = fakelag_group:textbox(pui.macros.dot .. " Watermark Text"),
   icons_page = fakelag_group:button(string.format("\a%s\xEE\x84\xB1\r %s Heroicons Library", pui.accent, pui.macros.dot_muted), function()
     panorama.open().SteamOverlayAPI.OpenExternalBrowserURL("https://heroicons.com/")
   end, true),
   guide = fakelag_group:button(string.format("\a%s\xEE\x84\xB4\r %s Print Instruction in Chat", pui.accent, pui.macros.dot_muted), function()
    if Class.ui.print_watermark_guide then Class.ui.print_watermark_guide() end
   end),
  },

  notifications = {
   -- created after Panel mount into Side block (see custom tab mount)
   lifetime = nil,
   max_items = nil,
   y_offset = nil,
   test = nil,
  },

  zoom_animation = {
   enabled = main_group:checkbox(pui.macros.dot .. " Zoom Animation"),
   speed = main_group:slider(pui.macros.dot_accent .. " Speed", 10, 100, 60, true, "%", 1),
  },

  aspect_ratio = (function()
   local label = pui.macros.dot .. " Aspect Ratio"
   return {
    enabled = main_group:checkbox(label),
    preset = main_group:combobox(hidden_control_ids.aspect_ratio_preset, "Custom", "5:4", "4:3", "16:10", "16:9"),
    amount = main_group:slider(hidden_slider_ids.aspect_ratio_amount, 1, 200, 100, true, "", 0.01),
   }
  end)(),
  viewmodel_changer = {
   enabled = main_group:checkbox(pui.macros.dot .. " Viewmodel Changer"),
   features = main_group:multiselect(pui.macros.dot_accent .. " Features", {"Opposite Knife Hand", "Remove Sleeves", "Lock Bob"}),
   position = {
    x = main_group:slider(hidden_slider_ids.viewmodel_position_x, -200, 200, 0, true, "x", 0.1),
    y = main_group:slider(hidden_slider_ids.viewmodel_position_y, -200, 200, 0, true, "y", 0.1),
    z = main_group:slider(hidden_slider_ids.viewmodel_position_z, -200, 200, 0, true, "z", 0.1),
   },
   fov = main_group:slider(hidden_slider_ids.viewmodel_fov, 540, 900, 680, true, "°", 0.1),
  },
  },
  },
  misc_tab = {
   event_logger = {
    enabled = main_group:checkbox(pui.macros.dot .. " Event Logger"),
    triggers = {
     event_triggers = main_group:multiselect(hidden_control_ids.event_logger_triggers, {"Aimbot", "Purchase", "Connection problems", "On Screen"}),
    },
    color = {
     hit_purchase_color = main_group:color_picker("\226\128\139", 255, 255, 255, 255),
     miss_connection_color = main_group:color_picker("\226\128\140", 225, 80, 80, 255),
    },
    prefix = main_group:textbox(pui.macros.dot_accent .. " Event Logger Prefix"),
    guide = main_group:button(string.format("\v\xEE\x84\xB4\r %s Print Instruction in Chat", pui.macros.dot_muted), function()
      if Class.ui.print_event_logger_guide then
        Class.ui.print_event_logger_guide()
      end
    end),
    force_teammate_aimbot = {
     enabled = main_group:checkbox(pui.macros.dot .. " Force Teammate Aimbot"),
     enemy_chat_viewer = main_group:checkbox(pui.macros.dot .. " Enemy Chat Viewer"),
    },
   },
  trash_talk = {
   enabled = main_group:checkbox(pui.macros.dot .. " Trash Talk"),
   mode = main_group:combobox(pui.macros.dot_accent .. " Trash Talk Mode", "Bait", "Author"),
   spectator_bait = main_group:checkbox(pui.macros.dot .. " While Spectating"),
   bait_triggers = main_group:multiselect(pui.macros.dot_accent .. " Bait Events", {"Kill", "Revenge"}),
   triggers = main_group:multiselect("\n", {"Kill", "Revenge", "Death"}),
   delay = main_group:slider(pui.macros.dot_accent .. " Send Time", 1, 20, 3, true, "s", 0.1),
   interval = main_group:slider(pui.macros.dot_accent .. " Message Interval", 9, 29, 12, true, "s", 0.1),
  },
  animation_breaker = {
   enabled = fakelag_group:checkbox(pui.macros.dot .. " Animation Breaker"),
   triggers = fakelag_group:multiselect(hidden_control_ids.animation_breaker_triggers, {"Air", "Legs", "Other"}),
   air = {
    mode = fakelag_group:combobox(pui.macros.dot_accent .. " Air Mode", "Kangaroo", "Static", "Allah"),
   },
  ground = {
   mode = fakelag_group:combobox(pui.macros.dot_accent .. " Legs Mode", "Jitter", "Static", "Moonwalk"),
   static_delta = fakelag_group:slider(pui.macros.dot_accent .. " Static Delta", 0, 100, 0, true, "%"),
   delta_from = fakelag_group:slider(pui.macros.dot_accent .. " Delta From", 0, 100, 0, true, "%"),
   delta_to = fakelag_group:slider(pui.macros.dot_accent .. " Delta To", 0, 100, 100, true, "%"),
   jitter_delay = fakelag_group:slider(pui.macros.dot_accent .. " Legs Delay", 1, 32, 2, true, "t"),
  },
  other = {
   mode = fakelag_group:multiselect(pui.macros.dot_accent .. " Mode\226\128\139", {"Body Lean", "Earthshake", "Leg movement"}),
   leg_movement = fakelag_group:combobox(pui.macros.dot_accent .. " Leg movement", "Off", "Always slide", "Never slide", "Break balance"),
   body_lean = fakelag_group:slider(pui.macros.dot_accent .. " Body Lean Strength", 0, 100, 0, true, "%", 1, {
    [0] = "Disabled",
    [10] = "Very Low",
    [25] = "Low",
    [40] = "Medium",
    [60] = "High",
    [80] = "Strong",
    [100] = "Maximum"
   }),
   allow_standing_leaning = fakelag_group:checkbox(pui.macros.dot .. " Allow Standing Leaning"),
   earthshake_strength = fakelag_group:slider(pui.macros.dot_accent .. " Earthshake Strength", 1, 100, 100, true, "%", 1, {
    [1] = "Min",
    [50] = "Half",
    [100] = "Max"
   }),
   walking_legs = fakelag_group:checkbox(pui.macros.dot .. " \aB4B465FFWalking Legs On Quick Peek\r"),
  },
  },
  console_enhancement = {
   mode = nil
  },
  clan_tag = {
   enabled = main_group:checkbox(pui.macros.dot .. " Clan Tag Spammer"),
  },
  discord_rpc = main_group:checkbox(pui.macros.dot .. " Discord RPC"),
  optimize_cvars = {
   enabled = main_group:checkbox(pui.macros.dot .. " Performance Optimizer"),
   mode = main_group:combobox(pui.macros.dot_accent .. " Optimization Profile", "Custom", "Balanced", "Performance", "Maximum FPS"),
   flags = main_group:combobox(pui.macros.dot_accent .. " Flags", "Always on", "Peeking"),
   options = main_group:multiselect(pui.macros.dot_accent .. " Cvars to Optimize", {
    "violence_hblood",
    "violence_ablood",
    "violence_hgibs",
    "violence_agibs",
    "cl_ragdoll_physics_enable",
    "ragdoll_sleepaftertime",
    "cl_ragdoll_collide",
    "r_eyemove",
    "r_eyegloss",
    "cl_csm_static_prop_shadows",
    "cl_csm_world_shadows",
    "cl_csm_viewmodel_shadows",
    "r_decals",
    "r_drawmodeldecals",
    "r_maxmodeldecal",
    "mp_decals",
    "r_drawdetailprops",
    "cl_detail_max_sway",
    "r_3dsky",
    "r_dynamic",
    "muzzleflash_light",
    "r_waterforceexpensive",
    "r_waterdrawreflection",
    "r_waterdrawrefraction",
    "cl_show_splashes",
    "rope_smooth",
    "rope_wind_dist",
    "rope_shake",
    "cl_ejectbrass",
    "func_break_max_pieces",
    "r_drawtracers",
    "r_drawtracers_firstperson",
    "cl_disablefreezecam",
    "cl_disablehtmlmotd",
    "cl_autohelp",
    "cl_showhelp"
   }),
  },
  addons = nil,
  warmup_setup = main_group:button(string.format("%s %s Warmup Setup", pui.macros.warmup_setup, pui.macros.dot_muted), function()
    Class.misc.warmup_setup:run()
  end)
},
config_tab = {
 -- Cloud toolbar is created before the list so it stays directly above it.
 cloud_view = main_group:combobox("\nCloud List", "My configs", "Explore", "Favorites", "Liked"),
 cloud_dislike = main_group:button(string.format("\a%s\xEE\x86\x9E\r", pui.accent), function()
  if Class.config then Class.config:_cloud_toggle_vote(-1) end
 end),
 cloud_like = main_group:button(string.format("\a%s\xEE\x86\x9F\r", pui.accent), function()
  if Class.config then Class.config:_cloud_toggle_vote(1) end
 end),
 cloud_refresh = main_group:button(string.format("\a%s\xEE\x84\x97\r", pui.accent), function()
  if Class.config then Class.config:refresh_cloud_list(false) end
 end),
 cloud_favorite = main_group:button(string.format("\a%s\xEE\x87\xB8\r", pui.accent), function()
  if Class.config then Class.config:_cloud_toggle_favorite() end
 end),
 list = main_group:listbox("\nConfig List", {"No configs"}),
 cloud_info = main_group:label("\aA0A0A0FFSelect a cloud config\r"),
 name = main_group:textbox(hidden_control_ids.config_name, ""),
 load_sections = main_group:multiselect("\n Load Sections", {"GameSense Settings", "Anti-Aim", "Visuals", "Misc"}),
 cloud_visibility = main_group:combobox("\nVisibility", "Private", "Public"),
 create = main_group:button(string.format("%s Create", pui.macros.config_create), function() Class.config:create_named() end),
 load = main_group:button(string.format("%s Load", pui.macros.config_load), function() Class.config:load_selected() end),
 save = main_group:button(string.format("%s Save", pui.macros.config_save), function() Class.config:save_named() end),
 delete = main_group:button(string.format("%s Delete", pui.macros.config_delete), function() Class.config:delete_selected() end),
 import = main_group:button(string.format("%s Import", pui.macros.config_import), function() Class.config:import_clipboard() end),
 export = main_group:button(string.format("%s Export", pui.macros.config_export), function() Class.config:export_clipboard() end),
 config_systems = nil,
},
}
local function setup_force_teammate_aimbot()
 local feature_group = Class.ui.menu.misc_tab.event_logger.force_teammate_aimbot
 local feature = feature_group and feature_group.enabled
 if not feature then return end
 local teammates_enemies = cvar and cvar.mp_teammates_are_enemies
 local target_teammates = nil
 pcall(function() target_teammates = ui.reference("RAGE", "Aimbot", "Target teammates") end)
 if not teammates_enemies then return end
 local saved_cvar, saved_target, active, busy = nil, nil, false, false
 local function read_cvar()
  local value
  pcall(function() value = tonumber(teammates_enemies:get_int()) end)
  return value
 end
 local function read_target()
  if not target_teammates then return nil end
  local value
  pcall(function() value = ui.get(target_teammates) and true or false end)
  return value
 end
 local function set_cvar(value) pcall(function() teammates_enemies:set_int(tonumber(value) or 0) end) end
 local function set_target(value)
  if not target_teammates or value == nil then return end
  pcall(ui.set, target_teammates, value and true or false)
 end
 local function apply()
  if busy then return end
  busy = true
  local enabled = false
  pcall(function() enabled = feature:get() and true or false end)
  if enabled then
   if not active then
    saved_cvar = read_cvar()
    saved_target = read_target()
    active = true
   end
   set_cvar(1)
   set_target(true)
  elseif active then
   set_cvar(saved_cvar or 0)
   set_target(saved_target)
   saved_cvar, saved_target, active = nil, nil, false
  end
  busy = false
 end
 feature:set_callback(apply)
 pcall(function()
  if target_teammates then
   ui.set_callback(target_teammates, function()
    if not busy and feature:get() then apply() end
   end)
  end
 end)
 Class.misc.force_teammate_aimbot = {
  apply = apply,
  restore = function()
   if not active then return end
   set_cvar(saved_cvar or 0)
   set_target(saved_target)
   saved_cvar, saved_target, active = nil, nil, false
  end,
 }
 apply()
end

setup_force_teammate_aimbot()

function play_state_action_sound(success)
  local sound = success and "ui/beepclear.wav" or "sound/ui/press_error.wav"
  local play = cvar and cvar.play
  if play and type(play.invoke_callback) == "function" then
    pcall(play.invoke_callback, play, sound)
  end
end

do
  local home = Class.ui.menu.home_tab

  local function apply_page_selector()
    local selected = home.page_selector:get()
    local page_to_route = {
      [MENU_ROUTES.page_home] = MENU_ROUTES.root_home,
      [MENU_ROUTES.page_antiaim] = MENU_ROUTES.root_antiaim,
      [MENU_ROUTES.page_visuals] = MENU_ROUTES.root_visuals,
      [MENU_ROUTES.page_misc] = MENU_ROUTES.root_misc,
    }
    local wanted = page_to_route[selected] or MENU_ROUTES.root_home
    if home.selected_tab.default:get() ~= wanted then home.selected_tab.default:set(wanted) end
  end
  home.page_selector:set_callback(apply_page_selector)
  apply_page_selector()
end

local antiaim_tab_active = {Class.ui.menu.home_tab.selected_tab.default, MENU_ROUTES.root_antiaim}
local visuals_tab_active = {Class.ui.menu.home_tab.selected_tab.default, MENU_ROUTES.root_visuals}
local misc_tab_active = {Class.ui.menu.home_tab.selected_tab.default, MENU_ROUTES.root_misc}
local misc_subtab_active = {Class.ui.menu.home_tab.selected_tab.miscellaneous, "Miscellaneous"}
local gamesense_settings_subtab_active = {Class.ui.menu.home_tab.selected_tab.miscellaneous, GAMESENSE_SETTINGS_VALUE}
-- Native fixes and GameSense settings live under Misc > GameSense settings.
local gamesense_settings_active = misc_tab_active
local config_tab_active = {Class.ui.menu.home_tab.selected_tab.default, MENU_ROUTES.root_home}
local antiaim_tab_builder_active = {Class.ui.menu.home_tab.selected_tab.antiaim, MENU_ROUTES.aa_builder}
local antiaim_tab_additional_active = {Class.ui.menu.home_tab.selected_tab.antiaim, MENU_ROUTES.aa_additional}
local visuals_tab_interface_active = {Class.ui.menu.home_tab.selected_tab.visuals, MENU_ROUTES.visuals_interface}
local visuals_tab_other_active = {Class.ui.menu.home_tab.selected_tab.visuals, MENU_ROUTES.visuals_other}
local home_panel_active = {Class.ui.menu.home_tab.selected_tab.default,
 MENU_ROUTES.root_home}
patch_pui_visibility(Class.ui.menu)
Class.ui.menu.home_tab.title:depend(home_panel_active)
Class.ui.menu.home_tab.info.user:depend(home_panel_active)
-- Username greeting stays visible even when navigating away from Home.
Class.ui.menu.home_tab.info.branch:depend(home_panel_active)
Class.ui.menu.home_tab.info.hitrate:depend(home_panel_active)
Class.ui.menu.home_tab.info.version:depend(home_panel_active)
Class.ui.menu.home_tab.info.session:depend(home_panel_active)
-- Native GameSense fixes remain on their dedicated settings page.
for _, control in ipairs({
 Class.ui.menu.gamesense_settings.accurate_quick_stop.enabled,
 Class.ui.menu.gamesense_settings.shot_delay_fix.enabled,
 Class.ui.menu.gamesense_settings.double_tap_stability_fix.enabled,
 Class.ui.menu.gamesense_settings.double_tap_return_fix.enabled,
 Class.ui.menu.gamesense_settings.animation_flag_preservation.enabled,
 Class.ui.menu.gamesense_settings.air_autostop.enabled,
 Class.ui.menu.gamesense_settings.scan_accuracy_optimization.enabled,
 Class.ui.menu.gamesense_settings.spread_autostop_fix.enabled,
}) do control:depend(gamesense_settings_active, gamesense_settings_subtab_active) end

-- Misc panel utilities belong to the Misc category on GameSense Settings.
local misc_panel_utilities = {
 Class.ui.menu.gamesense_settings.custom_quick_switch.enabled,
 Class.ui.menu.gamesense_settings.force_shot.enabled,
 Class.ui.menu.gamesense_settings.hide_shots_fakelag_fix.enabled,
 Class.ui.menu.gamesense_settings.defensive_double_tap_on_peek.enabled,
}
for _, control in ipairs(misc_panel_utilities) do control:depend(gamesense_settings_active, gamesense_settings_subtab_active) end
do
 local fs = Class.ui.menu.gamesense_settings.force_shot
 local on = {fs.enabled, true}
 for _, control in ipairs({
  fs.work_in_air, fs.hit_chance, fs.indicator,
 }) do
  control:depend(on, gamesense_settings_active, gamesense_settings_subtab_active)
 end
 fs.indicator_color:depend(on, {fs.indicator, true}, gamesense_settings_active, gamesense_settings_subtab_active)
 -- The Force Shot key is a native inline hotkey on the checkbox row, so its
 -- visibility is synced manually with the GameSense settings page.
 if type(fs.hotkey) == "number" then
  local selected_tab = Class.ui.menu.home_tab.selected_tab
  local function sync_force_shot_key()
   local visible = selected_tab.default:get() == MENU_ROUTES.root_misc
    and selected_tab.miscellaneous:get() == GAMESENSE_SETTINGS_VALUE
   pcall(ui.set_visible, fs.hotkey, visible)
  end
  selected_tab.default:set_callback(sync_force_shot_key)
  selected_tab.miscellaneous:set_callback(sync_force_shot_key)
  sync_force_shot_key()
 end
end

local backtrack_record_fix_menu = Class.ui.menu.gamesense_settings.backtrack_record_fix
backtrack_record_fix_menu.enabled:depend(gamesense_settings_active, gamesense_settings_subtab_active)
backtrack_record_fix_menu.lag_records:depend({backtrack_record_fix_menu.enabled, true}, gamesense_settings_active, gamesense_settings_subtab_active)
backtrack_record_fix_menu.extended_lag_records:depend({backtrack_record_fix_menu.enabled, true}, {backtrack_record_fix_menu.lag_records, true}, gamesense_settings_active, gamesense_settings_subtab_active)
backtrack_record_fix_menu.record_gap:depend({backtrack_record_fix_menu.enabled, true}, {backtrack_record_fix_menu.lag_records, true}, {backtrack_record_fix_menu.extended_lag_records, false}, gamesense_settings_active, gamesense_settings_subtab_active)
backtrack_record_fix_menu.extended_record_gap:depend({backtrack_record_fix_menu.enabled, true}, {backtrack_record_fix_menu.lag_records, true}, {backtrack_record_fix_menu.extended_lag_records, true}, gamesense_settings_active, gamesense_settings_subtab_active)

-- Keep the Record Gap value when switching between the normal and extended ranges.
if backtrack_record_fix_menu.extended_lag_records.set_callback then
 backtrack_record_fix_menu.extended_lag_records:set_callback(function()
  local extended = false
  pcall(function() extended = backtrack_record_fix_menu.extended_lag_records:get() and true or false end)
  if extended then
   local value = 3
   pcall(function() value = tonumber(backtrack_record_fix_menu.record_gap:get()) or 3 end)
   pcall(function() backtrack_record_fix_menu.extended_record_gap:set(math.max(1, math.min(20, math.floor(value)))) end)
  else
   local value = 3
   pcall(function() value = tonumber(backtrack_record_fix_menu.extended_record_gap:get()) or 3 end)
   pcall(function() backtrack_record_fix_menu.record_gap:set(math.max(1, math.min(10, math.floor(value)))) end)
  end
 end)
end

-- Reset on Shoot remains visible independently of the other fixes.
Class.ui.menu.gamesense_settings.fake_lag.reset_fake_lag_on_shot:depend(gamesense_settings_active, gamesense_settings_subtab_active)
Class.ui.menu.gamesense_settings.fake_lag.reset_delay_ticks:depend({Class.ui.menu.gamesense_settings.fake_lag.reset_fake_lag_on_shot, true}, gamesense_settings_active, gamesense_settings_subtab_active)

-- Native GameSense Fake Lag controls are left untouched; Reset on Shoot
-- remains a separate Lua feature alongside the GameSense settings fixes.


local uid = {}
for index = 1, #antiaim_conditions do
  uid[index] = string.rep(" ", index - 1)
end
local function copy_el(a, b)
  if not a or not b or not a.get or not b.set then return false end
  local success = pcall(b.set, b, a:get())
  return success
end
local function copy_state(src, dst)
  if not src or not dst then return false end
  local success = true
  local function copy(a, b)
    success = copy_el(a, b) and success
  end
  copy(src.override_state, dst.override_state)
  if src.bomb_e_fix and dst.bomb_e_fix then
    copy(src.bomb_e_fix, dst.bomb_e_fix)
  end
  if src.pitch and src.pitch.mode and dst.pitch and dst.pitch.mode then
    copy(src.pitch.mode, dst.pitch.mode)
    copy(src.pitch.value, dst.pitch.value)
  end
  if src.yaw and src.yaw.base and dst.yaw and dst.yaw.base then
    copy(src.yaw.base, dst.yaw.base)
  end
  copy(src.yaw.mode, dst.yaw.mode)
  copy(src.yaw.value, dst.yaw.value)
  copy(src.yaw.left_value, dst.yaw.left_value)
  copy(src.yaw.right_value, dst.yaw.right_value)
  copy(src.yaw.variability_value, dst.yaw.variability_value)
  copy(src.yaw.delay.mode, dst.yaw.delay.mode)
  copy(src.yaw.delay.features, dst.yaw.delay.features)
  copy(src.yaw.delay.freeze_chance, dst.yaw.delay.freeze_chance)
  copy(src.yaw.delay.freeze_time, dst.yaw.delay.freeze_time)
  copy(src.yaw.delay.freeze_cooldown, dst.yaw.delay.freeze_cooldown)
  copy(src.yaw.delay.disabling_chance, dst.yaw.delay.disabling_chance)
  copy(src.yaw.delay.disabling_time, dst.yaw.delay.disabling_time)
  copy(src.yaw.delay.custom.mode, dst.yaw.delay.custom.mode)
  copy(src.yaw.delay.custom.count, dst.yaw.delay.custom.count)
  for j = 1, 12 do
    copy(src.yaw.delay.custom.delays[j], dst.yaw.delay.custom.delays[j])
  end
  copy(src.yaw.modifier.mode, dst.yaw.modifier.mode)
  copy(src.yaw.modifier.value, dst.yaw.modifier.value)
  copy(src.yaw.modifier.ways, dst.yaw.modifier.ways)
  copy(src.yaw.modifier.variability_value, dst.yaw.modifier.variability_value)
  for wi = 1, 12 do
    copy(src.yaw.modifier.ways_offsets[wi], dst.yaw.modifier.ways_offsets[wi])
  end
  copy(src.body_yaw.mode, dst.body_yaw.mode)
  copy(src.body_yaw.value, dst.body_yaw.value)
  copy(src.body_yaw.direction, dst.body_yaw.direction)
  copy(src.body_yaw.left_value, dst.body_yaw.left_value)
  copy(src.body_yaw.right_value, dst.body_yaw.right_value)
  copy(src.body_yaw.inverter, dst.body_yaw.inverter)
  copy(src.force_defensive, dst.force_defensive)
  return success
end
local function read_state_value(element)
  return element and element.get and element:get() or nil
end
local function capture_state(builder)
  if not builder then return nil end
  local data = {
   v = 5,
   o = read_state_value(builder.override_state),
   be = read_state_value(builder.bomb_e_fix),
   fd = read_state_value(builder.force_defensive),
   p = {
    m = read_state_value(builder.pitch and builder.pitch.mode),
    v = read_state_value(builder.pitch and builder.pitch.value),
   },
  y = {
   b = read_state_value(builder.yaw.base),
   m = read_state_value(builder.yaw.mode),
   v = read_state_value(builder.yaw.value),
   l = read_state_value(builder.yaw.left_value),
   r = read_state_value(builder.yaw.right_value),
   rv = read_state_value(builder.yaw.variability_value),
   d = {
    m = read_state_value(builder.yaw.delay.mode),
    fi = read_state_value(builder.yaw.delay.freeze_inverter),
    fc = read_state_value(builder.yaw.delay.freeze_chance),
    ft = read_state_value(builder.yaw.delay.freeze_time),
    fk = read_state_value(builder.yaw.delay.freeze_cooldown),
    di = read_state_value(builder.yaw.delay.disabling),
    eo = read_state_value(builder.yaw.delay.disabling_when_exploits_off),
    c = {
     m = read_state_value(builder.yaw.delay.custom.mode),
     n = read_state_value(builder.yaw.delay.custom.count),
     d = {},
    },
  },
  x = {
   m = read_state_value(builder.yaw.modifier.mode),
   v = read_state_value(builder.yaw.modifier.value),
   w = read_state_value(builder.yaw.modifier.ways),
   rv = read_state_value(builder.yaw.modifier.variability_value),
   o = {},
  },
  },
  q = {
   m = read_state_value(builder.body_yaw.mode),
   v = read_state_value(builder.body_yaw.value),
   l = read_state_value(builder.body_yaw.left_value),
   r = read_state_value(builder.body_yaw.right_value),
   i = read_state_value(builder.body_yaw.inverter),
  },
  }
  for j = 1, 12 do
    data.y.d.c.d[j] = read_state_value(builder.yaw.delay.custom.delays[j])
  end
  for wi = 1, 12 do
    data.y.x.o[wi] = read_state_value(builder.yaw.modifier.ways_offsets[wi])
  end
  return data
end
function normalize_delay_mode(value, version)
  if type(value) == "number" then
    if version == 1 then
      if value == 1 then return "Disabled" end
      if value == 2 or value == 3 or value == 4 then return "Custom" end
    elseif version == 2 then
      if value == 1 or value == 2 then return "Custom" end
    elseif version == 3 then
      if value == 1 then return "Disabled" end
      if value == 2 or value == 3 then return "Custom" end
    end
  end
  if value == "Disabled" then return "Disabled" end
  if value == "Custom" or value == "Static" then return "Custom" end
  return "Disabled"
end
function normalize_custom_delay_mode(value)
  if value == 1 then return "Sequential" end
  if value == 2 then return "Smart Random" end
  if value == 3 then return "Random" end
  return value
end
local function apply_state_data(builder, data)
  if not builder or type(data) ~= "table" or (tonumber(data.v) ~= 1 and tonumber(data.v) ~= 2 and tonumber(data.v) ~= 3 and tonumber(data.v) ~= 4 and tonumber(data.v) ~= 5) then return false end
  local success = true
  local function set_value(element, value)
    if element == nil or value == nil then
      success = false
      return
    end
    local set_success = pcall(element.set, element, value)
    success = set_success and success
  end
  set_value(builder.override_state, data.o)
  if builder.force_defensive and data.fd ~= nil then
    set_value(builder.force_defensive, data.fd)
  end
  if builder.bomb_e_fix then
    set_value(builder.bomb_e_fix, data.be)
  end
  if builder.pitch and builder.pitch.mode then
    set_value(builder.pitch.mode, data.p and data.p.m)
    set_value(builder.pitch.value, data.p and data.p.v)
  end
  if builder.yaw and builder.yaw.base then
    set_value(builder.yaw.base, data.y and data.y.b)
  end
  set_value(builder.yaw.mode, data.y and data.y.m)
  set_value(builder.yaw.value, data.y and data.y.v)
  set_value(builder.yaw.left_value, data.y and data.y.l)
  set_value(builder.yaw.right_value, data.y and data.y.r)
  set_value(builder.yaw.variability_value, data.y and data.y.rv)
  local delay = data.y and data.y.d
  local raw_delay_mode = delay and delay.m
  local delay_version = tonumber(data.v)
  local legacy_fixed_delay = raw_delay_mode == "Static" or type(raw_delay_mode) == "number" and (
    (delay_version == 1 and (raw_delay_mode == 2 or raw_delay_mode == 3)) or
    (delay_version == 2 and raw_delay_mode == 1) or
    (delay_version == 3 and raw_delay_mode == 2)
  )
  local saved_delay_mode = normalize_delay_mode(raw_delay_mode, delay_version)
  set_value(builder.yaw.delay.mode, saved_delay_mode)
  local function set_optional_value(element, value)
    if value ~= nil then set_value(element, value) end
  end
  set_optional_value(builder.yaw.delay.freeze_inverter, delay and delay.fi)
  set_optional_value(builder.yaw.delay.freeze_chance, delay and delay.fc)
  set_optional_value(builder.yaw.delay.freeze_time, delay and delay.ft)
  set_optional_value(builder.yaw.delay.freeze_cooldown, delay and delay.fk)
  set_optional_value(builder.yaw.delay.disabling, delay and delay.di)
  set_optional_value(builder.yaw.delay.disabling_when_exploits_off, delay and delay.eo)
  local custom_delay = delay and delay.c
  set_value(builder.yaw.delay.custom.mode, legacy_fixed_delay and "Sequential" or normalize_custom_delay_mode(custom_delay and custom_delay.m))
  set_value(builder.yaw.delay.custom.count, legacy_fixed_delay and 1 or (custom_delay and custom_delay.n))
  for j = 1, 12 do
    local saved_custom_delay = custom_delay and custom_delay.d and custom_delay.d[j]
    if legacy_fixed_delay and j == 1 then
      saved_custom_delay = tonumber(delay and delay.v) or saved_custom_delay or 1
    end
    set_value(builder.yaw.delay.custom.delays[j], saved_custom_delay)
  end
  local modifier = data.y and data.y.x
  set_value(builder.yaw.modifier.mode, modifier and modifier.m)
  set_value(builder.yaw.modifier.value, modifier and modifier.v)
  local saved_ways = modifier and modifier.w
  if tonumber(data.v) < 5 then
    local legacy_ways = { [1] = 3, [2] = 5, [3] = 7, [4] = 9 }
    saved_ways = legacy_ways[tonumber(saved_ways)] or saved_ways
  end
  set_value(builder.yaw.modifier.ways, saved_ways)
  set_value(builder.yaw.modifier.variability_value, modifier and modifier.rv)
  for wi = 1, 12 do
    local saved_offset = modifier and modifier.o and modifier.o[wi]
    if saved_offset ~= nil then
      set_value(builder.yaw.modifier.ways_offsets[wi], saved_offset)
    end
  end
  local body_yaw = data.q
  set_value(builder.body_yaw.mode, body_yaw and body_yaw.m)
  set_value(builder.body_yaw.value, body_yaw and body_yaw.v)
  set_value(builder.body_yaw.left_value, body_yaw and body_yaw.l)
  set_value(builder.body_yaw.right_value, body_yaw and body_yaw.r)
  set_value(builder.body_yaw.inverter, body_yaw and body_yaw.i)
  return success
end
local function copy_state_to_clipboard(builder)
  local data = capture_state(builder)
  if not data or not Class.config or not Class.config._encode then return false end
  local success, encoded = pcall(function() return Class.config:_encode(data) end)
  if not success or type(encoded) ~= "string" or encoded == "" then return false end
  return pcall(clipboard.set, "afterglow_state_v1:" .. encoded)
end
local function paste_state_from_clipboard(builder)
  if not builder or not Class.config or not Class.config._decode then return false end
  local text = clipboard.get()
  if type(text) ~= "string" then return false end
  local encoded
  if text:sub(1, 19) == "afterglow_state_v1:" then
    encoded = text:sub(20)
  elseif text:sub(1, 19) == "gothsense_state_v1:" then
    encoded = text:sub(20)
  else
    return false
  end
  local success, data = pcall(function() return Class.config:_decode(encoded) end)
  if not success then return false end
  return apply_state_data(builder, data)
end
local TEAM_COLORS = {
 T = "\aE8B060FF",
 CT = "\a7AA2D4FF"
}
local BUILDER_GLYPHS = {
 pitch = string.char(0xEE, 0x85, 0xB4),
 delay = string.char(0xEE, 0x84, 0xA1),
 yaw = string.char(0xEE, 0x85, 0x8A),
 yaw_base = string.char(0xEE, 0x85, 0x83),
 modifier = string.char(0xEE, 0x85, 0x88),
 body = string.char(0xEE, 0x84, 0xBC),
 copy = string.char(0xEE, 0x86, 0x97),
 paste = string.char(0xEE, 0x86, 0x9C)
}
local function team_label(team, kind, fmt, ...)
  return TEAM_COLORS[team] .. BUILDER_GLYPHS[kind] .. "\r " .. string.format(fmt, ...)
end
local function action_label(kind, text)
  return string.format("\a%s%s\r \a%s%s\r", pui.accent, BUILDER_GLYPHS[kind], pui.accent, text)
end

local function make_builder(team, condition_name, id)
  local builder = {
   pitch = {},
   yaw = { delay = { custom = { delays = {} } }, modifier = { ways_offsets = {} } },
   body_yaw = {}
  }
  local function plain_label(fmt, ...)
    return pui.macros.dot_accent .. " " .. string.format(fmt, ...)
  end
  local function checkbox_label(fmt, ...)
    return pui.macros.dot .. " " .. string.format(fmt, ...)
  end
  builder.override_state = main_group:checkbox(checkbox_label("Override %s", condition_name))
  if condition_name == "Legit AA" then
    builder.bomb_e_fix = main_group:checkbox(checkbox_label("Fix E on bombsite%s", id))
  end
  if condition_name ~= "Legit AA" then
    builder.yaw.base = main_group:combobox(team_label(team, "yaw_base", "Yaw Base%s", id), "At targets", "Local view")
    builder.pitch.mode = main_group:combobox(team_label(team, "pitch", "Pitch%s", id), "Down", "Up", "Custom", "Random")
    builder.pitch.value = main_group:slider(plain_label("Pitch Value%s", id), -89, 89, 0, true, "°")
  end
  builder.yaw.mode = main_group:combobox(team_label(team, "yaw", "Yaw%s", id), "180", "L/R")
  builder.yaw.value = main_group:slider(plain_label("Value%s", id), -180, 180, 0, true, "°")
  builder.yaw.left_value = main_group:slider(plain_label("Left%s", id), -180, 180, 0, true, "°")
  builder.yaw.right_value = main_group:slider(plain_label("Right%s", id), -180, 180, 0, true, "°")
  builder.yaw.variability_value = main_group:slider(plain_label("Variability%s", id), 0, 100, 0, true, "%", 1, {[0] = "Disabled"})
  builder.yaw.delay.mode = fakelag_group:combobox(team_label(team, "delay", "Delay%s", id), "Disabled", "Custom")
  builder.yaw.delay.custom.mode = fakelag_group:combobox(plain_label("Mode%s", id), "Sequential", "Smart Random", "Random")
  builder.yaw.delay.custom.count = fakelag_group:slider(plain_label("Count%s", id), 1, 12, 1, true, "")
  for j = 1, 12 do
    builder.yaw.delay.custom.delays[j] = fakelag_group:slider(plain_label("Delay %d%s", j, id), 1, 32, 1, true, "t", 1, {[1] = "1t"})
  end
  builder.yaw.delay.features = fakelag_group:multiselect(team_label(team, "delay", "Features%s", id), "Freeze Inverter", "Disabling", "Affect Modifier to Delay")
  builder.yaw.delay.freeze_chance = fakelag_group:slider(plain_label("Freeze Chance%s", id), 1, 100, 30, true, "%")
  builder.yaw.delay.freeze_time = fakelag_group:slider(plain_label("Freeze Duration%s", id), 1, 80, 10, true, "t")
  builder.yaw.delay.freeze_cooldown = fakelag_group:slider(plain_label("Freeze Cooldown%s", id), 1, 16, 1, true, "t")
  builder.yaw.delay.disabling_chance = fakelag_group:slider(plain_label("Disabling Chance%s", id), 1, 100, 30, true, "%")
  builder.yaw.delay.disabling_time = fakelag_group:slider(plain_label("Disabling Time%s", id), 1, 80, 10, true, "t")
  builder.yaw.modifier.mode = main_group:combobox(team_label(team, "modifier", "Modifier%s", id), "Off", "Offset", "Center", "Random", "Skitter", "Ways", "G0BLIN")
  builder.yaw.modifier.value = main_group:slider(plain_label("Modifier Value%s", id), -180, 180, 0, true, "°")
  builder.yaw.modifier.ways = main_group:slider(plain_label("Ways%s", id), 1, 12, 3, true, "")
  for wi = 1, 12 do
    builder.yaw.modifier.ways_offsets[wi] = main_group:slider(plain_label("Way %d%s", wi, id), -180, 180, 0, true, "°")
  end
  builder.yaw.modifier.variability_value = main_group:slider(plain_label("Modifier Variability%s", id), 0, 100, 0, true, "%", 1, {[0] = "Disabled"})
  -- 180: Off / Opposite / Static / Jitter + Value + Direction (Static)
  -- L/R: Desync Left / Right only
  builder.body_yaw.mode = main_group:combobox(team_label(team, "body", "Desync%s", id), "Off", "Opposite", "Static", "Jitter")
  builder.body_yaw.value = main_group:slider(plain_label("Desync Value%s", id), -180, 180, 60, true, "°")
  builder.body_yaw.direction = main_group:combobox(team_label(team, "body", "Direction%s", id), "Left", "Right")
  builder.body_yaw.inverter = main_group:checkbox(team_label(team, "body", "Inverter%s", id))
  builder.body_yaw.left_value = main_group:slider(plain_label("Desync Left%s", id), 0, 60, 60, true, "°")
  builder.body_yaw.right_value = main_group:slider(plain_label("Desync Right%s", id), 0, 60, 60, true, "°")
  builder.force_defensive = main_group:checkbox(checkbox_label("Force Defensive%s", id))
  patch_pui_visibility(builder)
  return builder
end
local function bind_condition(builder, team_condition, condition_dependency, use_override)
  local tab = antiaim_tab_active
  local builder_tab = antiaim_tab_builder_active

  if use_override then
    pcall(function()
      builder.override_state:depend(tab, builder_tab, condition_dependency, team_condition)
    end)
  else
    pcall(function()
      builder.override_state:set(true)
      builder.override_state:set_visible(false)
    end)
  end

  local shared_dependencies = { tab, builder_tab, condition_dependency, team_condition }
  local function add_dependency(element, ...)
    if not element then return end
    local dependencies = {}
    for dependency_index = 1, select('#', ...) do
      dependencies[#dependencies + 1] = select(dependency_index, ...)
    end
    for dependency_index = 1, #shared_dependencies do
      dependencies[#dependencies + 1] = shared_dependencies[dependency_index]
    end
    if use_override then
      dependencies[#dependencies + 1] = { builder.override_state, true }
    end
    pcall(function() element:depend(unpack(dependencies)) end)
  end

  if builder.bomb_e_fix then
    add_dependency(builder.bomb_e_fix)
  end
  if builder.yaw.base then
    add_dependency(builder.yaw.base)
  end
  if builder.pitch.mode then
    add_dependency(builder.pitch.mode)
    add_dependency(builder.pitch.value, {builder.pitch.mode, "Custom"})
  end
  add_dependency(builder.yaw.mode)
  add_dependency(builder.yaw.value, {builder.yaw.mode, "180"})
  add_dependency(builder.yaw.left_value, {builder.yaw.mode, "L/R"})
  add_dependency(builder.yaw.right_value, {builder.yaw.mode, "L/R"})
  add_dependency(builder.yaw.variability_value, {builder.yaw.mode, "180", "L/R"})
  add_dependency(builder.yaw.delay.mode, {builder.yaw.mode, "L/R"})
  add_dependency(builder.yaw.delay.custom.mode, {builder.yaw.mode, "L/R"}, {builder.yaw.delay.mode, "Custom"})
  add_dependency(builder.yaw.delay.custom.count, {builder.yaw.mode, "L/R"}, {builder.yaw.delay.mode, "Custom"})
  for delay_index = 1, 12 do
    add_dependency(builder.yaw.delay.custom.delays[delay_index], {builder.yaw.mode, "L/R"}, {builder.yaw.delay.mode, "Custom"}, {builder.yaw.delay.custom.count, delay_index, 12})
  end
  add_dependency(builder.yaw.delay.features, {builder.yaw.mode, "L/R"}, {builder.yaw.delay.mode, "Custom"})
  add_dependency(builder.yaw.delay.freeze_chance, {builder.yaw.delay.features, "Freeze Inverter"}, {builder.yaw.mode, "L/R"}, {builder.yaw.delay.mode, "Custom"})
  add_dependency(builder.yaw.delay.freeze_time, {builder.yaw.delay.features, "Freeze Inverter"}, {builder.yaw.mode, "L/R"}, {builder.yaw.delay.mode, "Custom"})
  add_dependency(builder.yaw.delay.freeze_cooldown, {builder.yaw.delay.features, "Freeze Inverter"}, {builder.yaw.mode, "L/R"}, {builder.yaw.delay.mode, "Custom"})
  add_dependency(builder.yaw.delay.disabling_chance, {builder.yaw.delay.features, "Disabling"}, {builder.yaw.mode, "L/R"}, {builder.yaw.delay.mode, "Custom"})
  add_dependency(builder.yaw.delay.disabling_time, {builder.yaw.delay.features, "Disabling"}, {builder.yaw.mode, "L/R"}, {builder.yaw.delay.mode, "Custom"})
  add_dependency(builder.yaw.modifier.mode)
  add_dependency(builder.yaw.modifier.value, {builder.yaw.modifier.mode, "Offset", "Center", "Random", "Skitter", "G0BLIN"})
  add_dependency(builder.yaw.modifier.variability_value, {builder.yaw.modifier.mode, "Offset", "Center", "Random", "Skitter", "Ways", "G0BLIN"})
  add_dependency(builder.yaw.modifier.ways, {builder.yaw.modifier.mode, "Ways"})
  for way_index = 1, 12 do
    add_dependency(builder.yaw.modifier.ways_offsets[way_index],
      {builder.yaw.modifier.mode, "Ways"},
      {builder.yaw.modifier.ways, way_index, 12})
  end
  -- 180 → Body Yaw Off/Opposite/Static/Jitter; L/R → Desync Left/Right
  add_dependency(builder.body_yaw.mode, {builder.yaw.mode, "180"})
  add_dependency(builder.body_yaw.value, {builder.yaw.mode, "180"}, {builder.body_yaw.mode, "Jitter"})
  add_dependency(builder.body_yaw.direction, {builder.yaw.mode, "180"}, {builder.body_yaw.mode, "Static"})
  for _, element in ipairs({ builder.body_yaw.left_value, builder.body_yaw.right_value }) do
    add_dependency(element, {builder.yaw.mode, "L/R"})
  end
  add_dependency(builder.body_yaw.inverter, {builder.yaw.mode, "L/R"})
  add_dependency(builder.force_defensive)
  for _, element in ipairs({ builder.copy_button, builder.state_copy_button, builder.state_paste_button }) do
    add_dependency(element)
  end
end

-- Builders created first; Condition/Team/Copy live in Side (mounted later)
for index = 1, #antiaim_conditions do
  local condition_name = antiaim_conditions[index]
  local condition_id = uid[index]
  local terrorist_builder = make_builder("T", condition_name, condition_id)
  local counter_terrorist_builder = make_builder("CT", condition_name, condition_id)
  Class.ui.antiaim_conditions_t[index] = terrorist_builder
  Class.ui.antiaim_conditions_ct[index] = counter_terrorist_builder
end

-- Mount LUA A/B controls into the active page groups and activate tab
do
  local tab = (Class.ui and Class.ui._ag_tab) or _ag_tab
  if tab then
    -- Credits for the left Core block on non-builder routes; adopted into Core as its tail.
    local footer_core_group = pui.group("lua", "a")
    Class.ui.menu.footer_core = {
      title = footer_core_group:label("\aA0A0A0FF~ afterglow.yaw\r"),
      credits = footer_core_group:label("\aA0A0A0FFcrafted by lenora • 2026\r"),
    }
    pcall(function() tab:adopt_remaining(2, 1) end) -- active Core ← LUA A

    -- Keep the existing Misc panel (including Animation Breaker) unchanged.
    -- The two addon controls are created in their own lower Improvements block.
    pcall(function() tab:adopt_remaining(3, 2) end) -- Misc panel ← existing LUA B controls

    -- Side: Condition/Team/Copy (AA States) + Notifications
    do
      local side = pui.group("lua", "b")
      local select = Class.ui.menu.antiaim_tab.builder.select
      select.conditions_label = side:label(pui.macros.antiaim_conditions .. "   Condition")
      select.conditions = side:combobox("\n goth_builder_condition", antiaim_condition_options)
      select.team_label = side:label(pui.macros.team .. "   Team")
      select.team = side:combobox("\n goth_builder_team", antiaim_team_states)
      patch_pui_visibility(select)
      select.conditions_label:depend(antiaim_tab_active, antiaim_tab_builder_active)
      select.team_label:depend(antiaim_tab_active, antiaim_tab_builder_active)
      select.conditions:depend(antiaim_tab_active, antiaim_tab_builder_active)
      select.team:depend(
        antiaim_tab_active,
        antiaim_tab_builder_active,
        {select.conditions, antiaim_condition_options[1], antiaim_condition_options[2], antiaim_condition_options[3], antiaim_condition_options[4], antiaim_condition_options[5], antiaim_condition_options[6], antiaim_condition_options[7], antiaim_condition_options[8], antiaim_condition_options[9], antiaim_condition_options[10]}
      )

      for index = 1, #antiaim_conditions do
        local condition_index = index
        local layout_suffix = string.rep("\226\128\139", index)
        local send_text = "Send to Opposite side"
        local copy_label = string.format("%s \a%s%s\r", pui.macros.dot, pui.accent, send_text)
        local half = math.max(8, math.floor(#send_text / 2))
        local function pad_half(text)
          text = tostring(text or "")
          local pad = math.max(0, half - #text)
          local left = math.floor(pad / 2)
          local right = pad - left
          return string.rep(" ", left) .. text .. string.rep(" ", right)
        end
        local copy_text = action_label("copy", pad_half("Copy"))
        local paste_text = action_label("paste", pad_half("Paste"))
        local terrorist_builder = Class.ui.antiaim_conditions_t[condition_index]
        local counter_terrorist_builder = Class.ui.antiaim_conditions_ct[condition_index]
        terrorist_builder.copy_button = side:button(copy_label, function()
          local ok = copy_state(Class.ui.antiaim_conditions_t[condition_index], Class.ui.antiaim_conditions_ct[condition_index])
          play_state_action_sound(ok)
        end)
        terrorist_builder.state_copy_button = side:button(copy_text, function()
          local ok = copy_state_to_clipboard(Class.ui.antiaim_conditions_t[condition_index])
          play_state_action_sound(ok)
        end)
        terrorist_builder.state_paste_button = side:button(paste_text, function()
          local active_builder = Class.ui.antiaim_conditions_t[condition_index]
          local ok = paste_state_from_clipboard(active_builder)
          if ok and Class.config and Class.config._save_ui_autosave then
            pcall(Class.config._save_ui_autosave, Class.config)
          end
          play_state_action_sound(ok)
        end, true)
        counter_terrorist_builder.copy_button = side:button(copy_label .. layout_suffix, function()
          local ok = copy_state(Class.ui.antiaim_conditions_ct[condition_index], Class.ui.antiaim_conditions_t[condition_index])
          play_state_action_sound(ok)
        end)
        counter_terrorist_builder.state_copy_button = side:button(copy_text .. layout_suffix, function()
          local ok = copy_state_to_clipboard(Class.ui.antiaim_conditions_ct[condition_index])
          play_state_action_sound(ok)
        end)
        counter_terrorist_builder.state_paste_button = side:button(paste_text .. layout_suffix, function()
          local active_builder = Class.ui.antiaim_conditions_ct[condition_index]
          local ok = paste_state_from_clipboard(active_builder)
          if ok and Class.config and Class.config._save_ui_autosave then
            pcall(Class.config._save_ui_autosave, Class.config)
          end
          play_state_action_sound(ok)
        end, true)

        -- Keep each State Copy/Paste pair registered with its matching
        -- Send to Opposite Side button so the native layout pass can size
        -- the pair to exactly the same available width.
        Class.ui._builder_action_rows[#Class.ui._builder_action_rows + 1] = {
          terrorist_builder.copy_button,
          terrorist_builder.state_copy_button,
          terrorist_builder.state_paste_button,
        }
        Class.ui._builder_action_rows[#Class.ui._builder_action_rows + 1] = {
          counter_terrorist_builder.copy_button,
          counter_terrorist_builder.state_copy_button,
          counter_terrorist_builder.state_paste_button,
        }
      end

      for index = 1, #antiaim_conditions do
        local condition_dependency = {Class.ui.menu.antiaim_tab.builder.select.conditions, antiaim_condition_options[index]}
        local terrorist_condition = {Class.ui.menu.antiaim_tab.builder.select.team, antiaim_team_states[1]}
        local counter_terrorist_condition = {Class.ui.menu.antiaim_tab.builder.select.team, antiaim_team_states[2]}
        local use_override = index ~= 1
        bind_condition(Class.ui.antiaim_conditions_t[index], terrorist_condition, condition_dependency, use_override)
        bind_condition(Class.ui.antiaim_conditions_ct[index], counter_terrorist_condition, condition_dependency, use_override)
      end

      -- Mount States alone in its own native category before creating the
      -- independent Notifications card.
      pcall(function() tab:adopt_remaining(4, 2) end)

      local notifications_group = pui.group("lua", "b")
      local n = Class.ui.menu.visuals_tab.other.notifications
      n.lifetime = notifications_group:slider(pui.macros.dot .. " Lifetime", 10, 100, 30, true, "s", 0.1)
      n.max_items = notifications_group:slider(pui.macros.dot .. " Max Notifications", 1, 10, 5, true)
      n.y_offset = notifications_group:slider(pui.macros.dot .. " Y Offset", 0, 600, 80, true, "px", 1)
      n.test = notifications_group:button(string.format("\a%s\xEE\x84\xB4\r %s Send Notification", pui.accent, pui.macros.dot_muted), function()
        if Class.render and Class.render.notifications then
          Class.render.notifications:push("/rTest /vnotification/r", "info")
        end
      end)
      patch_pui_visibility(n)
      pcall(function()
        n.lifetime:depend(visuals_tab_active)
        n.max_items:depend(visuals_tab_active)
        n.y_offset:depend(visuals_tab_active)
        n.test:depend(visuals_tab_active)
      end)
      pcall(function() tab:adopt_remaining(6, 2) end)

      -- Thankfulness credits are mounted into their own native category.
      local thankfulness_group = pui.group("lua", "b")
      local thankfulness_credits = {
        thankfulness_group:label("\aB4B465FFSwiftyy — \aA0A0A0FFSupport\r"),
        thankfulness_group:label("\aB4B465FFSkeetback — \aA0A0A0FFIdeas\r"),
        thankfulness_group:label("\aB4B465FFKesha Neverlose — \aA0A0A0FFTesting\r"),
        thankfulness_group:label("\aB4B465FFNeonew — \aA0A0A0FFSupporting with code and reversing\r"),
        thankfulness_group:label("\aB4B465FFHakkai — \aA0A0A0FFЯ уничтожу твою пасту\r"),
      }
      patch_pui_visibility(thankfulness_credits)
      for index = 1, #thankfulness_credits do
        pcall(function() thankfulness_credits[index]:depend(misc_tab_active, gamesense_settings_subtab_active) end)
      end

      pcall(function() tab:adopt_remaining(7, 2) end)

      -- Improvements is a separate native category, independent of Thankfulness.
      local improvements_group = pui.group("lua", "b")
      local misc = Class.ui.menu.misc_tab
      misc.console_enhancement.mode = improvements_group:combobox(pui.macros.dot .. " Console Addons",
        "Off",
        "Console Filter",
        "Clean On Level Init",
        "Clean On New Round"
      )
      misc.addons = improvements_group:multiselect(pui.macros.dot .. " Addons", {
        "Allow Duck on FD",
        "Unlock Hidden Cvars"
      })
      patch_pui_visibility({ misc.console_enhancement.mode, misc.addons })
      pcall(function() tab:adopt_remaining(8, 2) end)
    end

    -- Navigate: root + sub comboboxes (no labels, synced)
    do
      local nav = pui.group("lua", "b")

      local page_buttons = {
        {page = MENU_ROUTES.page_home, route = MENU_ROUTES.root_home, icon = pui.macros.home, text = "Home"},
        {page = MENU_ROUTES.page_antiaim, route = MENU_ROUTES.root_antiaim, icon = pui.macros.antiaim, text = "Anti-Aim"},
        {page = MENU_ROUTES.page_visuals, route = MENU_ROUTES.root_visuals, icon = pui.macros.visuals, text = "Visuals"},
        {page = MENU_ROUTES.page_misc, route = MENU_ROUTES.root_misc, icon = string.format("\a%s\xEE\x84\x95\r", pui.accent), text = "Misc"},
      }
      local refresh_sub_visibility

      local function select_root(route)
        if not route then return end
        local home = Class.ui.menu.home_tab
        if home and home.selected_tab and home.selected_tab.default then
          if home.selected_tab.default:get() ~= route then
            home.selected_tab.default:set(route)
          end
        end
        local selected = nil
        for index = 1, #page_buttons do
          if page_buttons[index].route == route then
            selected = page_buttons[index].page
            break
          end
        end
        if selected and home and home.page_selector then
          pcall(function()
            if home.page_selector:get() ~= selected then home.page_selector:set(selected) end
          end)
        end
        if refresh_sub_visibility then refresh_sub_visibility() end
        if Class.ui.update_menu then pcall(Class.ui.update_menu) end
      end

      local function make_page_button_label(item)
        -- Icon-only navigation; symmetric padding keeps each glyph visually centered
        -- inside the equal-width 4x1 button cells.
        local target_chars = 4
        local icon_chars = #tostring(item.icon or "")
        local padding = math.max(0, target_chars - icon_chars)
        local left = math.floor(padding / 2)
        local right = padding - left
        return string.rep(" ", left) .. tostring(item.icon or "") .. string.rep(" ", right)
      end

      local root_buttons = {}
      for index = 1, #page_buttons do
        local item = page_buttons[index]
        local route = item.route
        root_buttons[index] = nav:button(make_page_button_label(item), function()
          select_root(route)
        end)
      end
      Class.ui._nav_tabs = root_buttons

      -- sub tabs per section
      local sub_aa = nav:combobox("\n afterglow_nav_sub_aa", MENU_ROUTES.aa_builder, MENU_ROUTES.aa_additional)
      local sub_vis = nav:combobox("\n afterglow_nav_sub_vis", MENU_ROUTES.visuals_interface, MENU_ROUTES.visuals_other)
      local sub_misc = nav:combobox("\n afterglow_nav_sub_misc", MISCELLANEOUS_OPTION, GAMESENSE_SETTINGS_OPTION)
      Class.ui._nav_sub = { aa = sub_aa, vis = sub_vis, misc = sub_misc }
      patch_pui_visibility(Class.ui._nav_sub)

      local function current_root()
        local home = Class.ui.menu.home_tab
        if home and home.selected_tab and home.selected_tab.default then
          return home.selected_tab.default:get()
        end
        return MENU_ROUTES.root_home
      end

      refresh_sub_visibility = function()
        local root = current_root()
        local is_aa = root == MENU_ROUTES.root_antiaim
        local is_vis = root == MENU_ROUTES.root_visuals
        local is_misc = root == MENU_ROUTES.root_misc
        pcall(function() sub_aa:set_visible(is_aa) end)
        pcall(function() sub_vis:set_visible(is_vis) end)
        pcall(function() sub_misc:set_visible(is_misc) end)
      end

      sub_aa:set_callback(function()
        local home = Class.ui.menu.home_tab
        if home and home.selected_tab and home.selected_tab.antiaim then
          local v = sub_aa:get()
          if home.selected_tab.antiaim:get() ~= v then home.selected_tab.antiaim:set(v) end
        end
        if Class.ui.update_menu then pcall(Class.ui.update_menu) end
      end)
      sub_vis:set_callback(function()
        local home = Class.ui.menu.home_tab
        if home and home.selected_tab and home.selected_tab.visuals then
          local v = sub_vis:get()
          if home.selected_tab.visuals:get() ~= v then home.selected_tab.visuals:set(v) end
        end
        if Class.ui.update_menu then pcall(Class.ui.update_menu) end
      end)
      sub_misc:set_callback(function()
        local home = Class.ui.menu.home_tab
        if home and home.selected_tab and home.selected_tab.miscellaneous then
          local selected_option = sub_misc:get()
          local internal_value = selected_option == MISCELLANEOUS_OPTION
            and "Miscellaneous" or GAMESENSE_SETTINGS_VALUE
          if home.selected_tab.miscellaneous:get() ~= internal_value then
            home.selected_tab.miscellaneous:set(internal_value)
          end
        end
        if Class.ui.update_menu then pcall(Class.ui.update_menu) end
      end)

      Class.ui._sync_nav_tabs = function(root)
        local home = Class.ui.menu.home_tab
        if home and home.selected_tab then
          pcall(function()
            if home.selected_tab.antiaim and sub_aa:get() ~= home.selected_tab.antiaim:get() then
              sub_aa:set(home.selected_tab.antiaim:get())
            end
            if home.selected_tab.visuals and sub_vis:get() ~= home.selected_tab.visuals:get() then
              sub_vis:set(home.selected_tab.visuals:get())
            end
            if home.selected_tab.miscellaneous then
              local internal_value = home.selected_tab.miscellaneous:get()
              local nav_value = internal_value == GAMESENSE_SETTINGS_VALUE
                and GAMESENSE_SETTINGS_OPTION or MISCELLANEOUS_OPTION
              if sub_misc:get() ~= nav_value then sub_misc:set(nav_value) end
            end
          end)
        end
        refresh_sub_visibility()
      end

      refresh_sub_visibility()

      pcall(function() tab:adopt_remaining(1, 2) end)
    end

    pcall(function() tab:activate() end)
    -- Keep custom-tab activation silent; no startup/debug console output.
    Class.ui._custom_tab = tab
    for category_index = 1, 11 do
      pcall(function()
        tab:configure_category(category_index, {lock_layout = true})
      end)
    end

    -- Do not modify native menu width/height while loading or unloading.
    client.set_event_callback("shutdown", function()
      pcall(function() tab:destroy() end)
    end)
  end

  -- Join the Network has its own native category, separate from States,
  -- Notifications, Thankfulness and Improvements.
  do
    local network_group = pui.group("lua", "b")
    local network = Class.ui.menu.home_tab.network
    network.choose = network_group:slider(
      pui.macros.dot .. " Socials", 1, 3, 1, true, "", 1,
      {
        [1] = "\a8B96C9E8Discord\r",
        [2] = "\a79AFC7E8Telegram\r",
        [3] = "\aC97878E8Youtube (Lenora)\r"
      }
    )
    network.button = network_group:button(
      string.format("\v\xEE\x84\xAB\r %s Open Page", pui.macros.dot_muted),
      Class.util.open_network_link
    )
    -- Config Systems belongs to Home / Network, directly below Open Page.
    network.config_systems = network_group:combobox(pui.macros.dot .. " Config Systems", "Local", "Cloud")
    Class.ui.menu.config_tab.config_systems = network.config_systems

    -- Cloud backend endpoint and credentials are managed internally.
    -- The only visible control here is the Local / Cloud selector.
    network.choose:depend(home_panel_active)
    network.button:depend(home_panel_active)
    network.config_systems:depend(home_panel_active)
    if tab then
      pcall(function() tab:adopt_remaining(9, 2) end)
    end
  end
end

-- Home Manipulations lives in its own native category directly below Home.
-- Create these controls after the Home/Network mounts so they are adopted only
-- by category 5 instead of being included in the main Home panel.
local default_username = tostring(rawget(_G, "_USERNAME") or "")
default_username = default_username:gsub("[%c]", ""):gsub("^%s+", ""):gsub("%s+$", "")
if default_username == "" then default_username = "user" end
local home_manipulations_group = pui.group("lua", "b")
local home_manipulations_info = {
  home_manipulations_group:label("\aB4B465FF\xEE\x83\x9B\r   \aB4B465FFFeatures highlighted in this color\r"),
  home_manipulations_group:label("\aB4B465FFuse Skeet memory to apply their changes.\r"),
  home_manipulations_group:label("\aB4B465FFUse them at your own risk.\r"),
}
for index = 1, #home_manipulations_info do
  pcall(function() home_manipulations_info[index]:depend(home_panel_active) end)
end
Class.ui.menu.home_tab.username = home_manipulations_group:combobox(pui.macros.dot .. " Username", "Loader", "Steam")
Class.ui.menu.home_tab.mellstroy_mode = home_manipulations_group:checkbox(pui.macros.dot .. " Mellstroy Mode")
Class.ui.menu.home_tab.username:depend(home_panel_active)
Class.ui.menu.home_tab.mellstroy_mode:depend(home_panel_active)

local function steam_persona_name()
  local ok, name = pcall(function() return panorama.open().MyPersonaAPI.GetName() end)
  if ok and type(name) == "string" and name ~= "" then return name end
  return nil
end

local function apply_username()
  local choice = "Loader"
  pcall(function() choice = Class.ui.menu.home_tab.username:get() or "Loader" end)
  if choice == "Steam" then
    local steam_name = steam_persona_name()
    steam_name = tostring(steam_name or ""):gsub("[%c]", ""):gsub("^%s+", ""):gsub("%s+$", "")
    user_database.username = steam_name ~= "" and steam_name:sub(1, 24) or default_username
  else
    -- Includes old saved "Custom" values: they now resolve to Loader.
    user_database.username = default_username
  end
  local username = tostring(user_database.username or ""):gsub("[%c]", ""):gsub("^%s+", ""):gsub("%s+$", "")
  if username == "" then
    username = default_username ~= "" and default_username or "user"
    user_database.username = username
  end
  local f = Class.util.accent_color.first
  local ok, formatted = pcall(Class.render.gradient_text, username, 2.5, 2,
    f[1], f[2], f[3], 255, f[1] * 0.75, f[2] * 0.75, f[3] * 0.75, 255)
  local display_username = ok and type(formatted) == "string" and formatted ~= "" and formatted or username
  local welcome_text = "Welcome, " .. display_username
  pcall(function() Class.ui.menu.home_tab.info.user:set(welcome_text) end)
end
Class.ui.menu.home_tab.username:set_callback(apply_username, true)

do
  local tab = Class.ui._custom_tab or Class.ui._ag_tab
  if tab then pcall(function() tab:adopt_remaining(5, 2) end) end
end
apply_username()

local hotkeys = Class.ui.menu.antiaim_tab.additional.hotkey
hotkeys.freestanding:depend(antiaim_tab_active, antiaim_tab_additional_active)
hotkeys.body_freestanding:depend(antiaim_tab_active, antiaim_tab_additional_active)
hotkeys.prefer_manual:depend(antiaim_tab_active, antiaim_tab_additional_active)
pcall(hotkeys.prefer_manual.set, hotkeys.prefer_manual, true)
Class.ui.menu.antiaim_tab.additional.hotkey.freestanding_disablers:depend(antiaim_tab_active, antiaim_tab_additional_active)
Class.ui.menu.antiaim_tab.additional.hotkey.manual_forward:depend(antiaim_tab_active, antiaim_tab_additional_active)
Class.ui.menu.antiaim_tab.additional.hotkey.manual_left:depend(antiaim_tab_active, antiaim_tab_additional_active)
Class.ui.menu.antiaim_tab.additional.hotkey.manual_mode:depend(antiaim_tab_active, antiaim_tab_additional_active)
Class.ui.menu.antiaim_tab.additional.hotkey.manual_right:depend(antiaim_tab_active, antiaim_tab_additional_active)
local builder_fakelag = Class.ui.menu.antiaim_tab.additional.fakelag
-- Keep Force Defensive after the Builder controls in the Anti-Aim Angles column.
builder_fakelag.break_lc = { enabled = nil }
-- Builder Fake Lag column: native Fake Lag settings plus Tickbase Control.
builder_fakelag.tickbase_enabled = fakelag_group:checkbox(pui.macros.dot .. " \aB4B465FFTickbase Control\r")
builder_fakelag.tickbase = fakelag_group:slider("\n", 1, 22, 14, true, "t", 1, {[14] = "GS"})
builder_fakelag.anti_bruteforce.enabled:depend(antiaim_tab_active, antiaim_tab_additional_active)
builder_fakelag.anti_bruteforce.conditions:depend({builder_fakelag.anti_bruteforce.enabled, true}, antiaim_tab_active, antiaim_tab_additional_active)
builder_fakelag.anti_bruteforce.timeout:depend({builder_fakelag.anti_bruteforce.enabled, true}, antiaim_tab_active, antiaim_tab_additional_active)
builder_fakelag.anti_bruteforce.mode:depend({builder_fakelag.anti_bruteforce.enabled, true}, antiaim_tab_active, antiaim_tab_additional_active)
builder_fakelag.anti_bruteforce.notify:depend({builder_fakelag.anti_bruteforce.enabled, true}, antiaim_tab_active, antiaim_tab_additional_active)
-- First-run default: Event Logger and On Screen notifications are enabled.
pcall(function() builder_fakelag.anti_bruteforce.notify:set({"Event Logger", "On Screen"}) end)
builder_fakelag.tickbase_enabled:depend(antiaim_tab_active, antiaim_tab_builder_active)
builder_fakelag.tickbase:depend({builder_fakelag.tickbase_enabled, true}, antiaim_tab_active, antiaim_tab_builder_active)
-- Pull late LUA B controls (tickbase) into Panel
do
  local tab = Class.ui._custom_tab or Class.ui._ag_tab
  if tab then pcall(function() tab:adopt_remaining(3, 2) end) end
end

-- Defensive AA card at the bottom of the left column, BUILDER ONLY. Holds the native defensive
-- anti-aim settings (emberlash-style feature set; force_defensive is NOT touched) plus the
-- builder-route credits. On other routes the left Core block keeps its full previous height and
-- carries its own credits (footer_core); this card is hidden there.
do
  local defensive_aa_group = pui.group("lua", "b")
  local dot = pui.macros.dot
  local da = {
    enabled = defensive_aa_group:checkbox(dot .. " Defensive anti-aim"),
    triggers = defensive_aa_group:multiselect(pui.macros.dot_accent .. " Triggers", { "Double Tap", "Hide Shots", "On Shot" }),
    -- Yaw
    yaw_type = defensive_aa_group:combobox(pui.macros.dot_accent .. " Yaw", "Custom", "Cross switch", "Three point", "Wide switch", "Spin", "Distortion", "Random"),
    yaw_offset = defensive_aa_group:slider(pui.macros.dot_accent .. " Yaw Offset", -180, 180, 0, true, "\194\176"),
    yaw_offset_randomize = defensive_aa_group:slider(pui.macros.dot_accent .. " Yaw Randomize", 0, 100, 0, true, "%"),
    yaw_speed = defensive_aa_group:slider(pui.macros.dot_accent .. " Yaw Speed", 1, 75, 10, true),
    -- L/R addition
    l_r_addition = defensive_aa_group:checkbox(dot .. " L/R Addition"),
    left_offset = defensive_aa_group:slider(pui.macros.dot_accent .. " Left Offset", -180, 180, 0, true, "\194\176"),
    left_offset_randomize = defensive_aa_group:slider(pui.macros.dot_accent .. " Left Randomize", 0, 100, 0, true, "%"),
    right_offset = defensive_aa_group:slider(pui.macros.dot_accent .. " Right Offset", -180, 180, 0, true, "\194\176"),
    right_offset_randomize = defensive_aa_group:slider(pui.macros.dot_accent .. " Right Randomize", 0, 100, 0, true, "%"),
    -- Yaw jitter
    yaw_jitter = defensive_aa_group:combobox(pui.macros.dot_accent .. " Yaw Jitter", "Off", "Offset", "Center", "Random", "Skitter", "Spin", "Multi-way"),
    jitter_offset = defensive_aa_group:slider(pui.macros.dot_accent .. " Jitter Offset", -180, 180, 0, true, "\194\176"),
    jitter_offset_randomize = defensive_aa_group:slider(pui.macros.dot_accent .. " Jitter Randomize", 0, 100, 0, true, "%"),
    jitter_speed = defensive_aa_group:slider(pui.macros.dot_accent .. " Jitter Speed", 1, 75, 10, true),
    jitter_ways = defensive_aa_group:slider(pui.macros.dot_accent .. " Jitter Ways", 3, 8, 3, true),
    -- Body desync
    body_yaw = defensive_aa_group:combobox(pui.macros.dot_accent .. " Body Yaw", "Keep", "Off", "Jitter", "Static"),
    body_left = defensive_aa_group:slider(pui.macros.dot_accent .. " Body Left", 0, 60, 60, true, "\194\176"),
    body_right = defensive_aa_group:slider(pui.macros.dot_accent .. " Body Right", 0, 60, 60, true, "\194\176"),
    body_left_randomize = defensive_aa_group:slider(pui.macros.dot_accent .. " Body Left Randomize", 0, 100, 0, true, "%"),
    body_right_randomize = defensive_aa_group:slider(pui.macros.dot_accent .. " Body Right Randomize", 0, 100, 0, true, "%"),
    -- Delay
    delay = defensive_aa_group:combobox(pui.macros.dot_accent .. " Delay", "Off", "Static", "Random", "Smart", "Fluctuate", "Ways"),
    l_r_delay = defensive_aa_group:checkbox(dot .. " L/R Delay"),
    delay_value = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Value", 1, 22, 1, true, "t"),
    delay_min = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Min", 1, 22, 1, true, "t"),
    delay_max = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Max", 1, 22, 1, true, "t"),
    delay_variability = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Variability", 0, 100, 0, true, "%"),
    delay_value_left = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Left", 1, 22, 1, true, "t"),
    delay_min_left = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Min Left", 1, 22, 1, true, "t"),
    delay_max_left = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Max Left", 1, 22, 1, true, "t"),
    delay_variability_left = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Var Left", 0, 100, 0, true, "%"),
    delay_value_right = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Right", 1, 22, 1, true, "t"),
    delay_min_right = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Min Right", 1, 22, 1, true, "t"),
    delay_max_right = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Max Right", 1, 22, 1, true, "t"),
    delay_variability_right = defensive_aa_group:slider(pui.macros.dot_accent .. " Delay Var Right", 0, 100, 0, true, "%"),
    -- Pitch
    pitch_type = defensive_aa_group:combobox(pui.macros.dot_accent .. " Pitch", "Off", "Custom", "Cross switch", "Three point", "Five point", "Pendulum", "Edge sweep", "Random"),
    pitch_offset = defensive_aa_group:slider(pui.macros.dot_accent .. " Pitch Offset", -89, 89, 0, true, "\194\176"),
    pitch_offset_randomize = defensive_aa_group:slider(pui.macros.dot_accent .. " Pitch Randomize", 0, 100, 0, true, "%"),
    pitch_speed = defensive_aa_group:slider(pui.macros.dot_accent .. " Pitch Speed", 1, 75, 10, true),
  }
  Class.ui.menu.antiaim_tab.additional.defensive_aa = da
  da.enabled:depend(antiaim_tab_active)
  local base_keys = { "triggers", "yaw_type", "yaw_offset", "yaw_offset_randomize", "yaw_speed",
    "l_r_addition", "yaw_jitter", "jitter_offset", "jitter_offset_randomize", "jitter_speed", "jitter_ways",
    "body_yaw", "body_left", "body_right", "body_left_randomize", "body_right_randomize",
    "delay", "l_r_delay", "delay_value", "delay_min", "delay_max", "delay_variability",
    "pitch_type", "pitch_offset", "pitch_offset_randomize", "pitch_speed" }
  for _, key in ipairs(base_keys) do
    da[key]:depend({ da.enabled, true }, antiaim_tab_active)
  end
  -- L/R addition offsets
  for _, key in ipairs({ "left_offset", "left_offset_randomize", "right_offset", "right_offset_randomize" }) do
    da[key]:depend({ da.enabled, true }, { da.l_r_addition, true }, antiaim_tab_active)
  end
  -- Jitter mode-specific
  da.jitter_speed:depend({ da.yaw_jitter, "Spin" })
  da.jitter_ways:depend({ da.yaw_jitter, "Multi-way" })
  -- Body limits only for Jitter/Static
  for _, key in ipairs({ "body_left", "body_right", "body_left_randomize", "body_right_randomize" }) do
    da[key]:depend({ da.body_yaw, "Keep", true }, { da.body_yaw, "Off", true })
  end
  -- Delay shared fields
  da.l_r_delay:depend({ da.delay, "Off", true })
  da.delay_value:depend({ da.delay, "Off", true }, { da.delay, "Random", true }, { da.delay, "Fluctuate", true }, { da.l_r_delay, true })
  for _, key in ipairs({ "delay_min", "delay_max", "delay_variability" }) do
    da[key]:depend({ da.delay, "Off", true }, { da.delay, "Static", true }, { da.l_r_delay, true })
  end
  -- Delay per-side fields
  for _, side in ipairs({ "left", "right" }) do
    da["delay_value_" .. side]:depend({ da.enabled, true }, { da.l_r_delay, true }, { da.delay, "Off", true }, { da.delay, "Random", true }, { da.delay, "Fluctuate", true }, antiaim_tab_active)
    for _, f in ipairs({ "min", "max", "variability" }) do
      da["delay_" .. f .. "_" .. side]:depend({ da.enabled, true }, { da.l_r_delay, true }, { da.delay, "Off", true }, { da.delay, "Static", true }, antiaim_tab_active)
    end
  end
  -- Pitch mode-specific
  da.pitch_offset:depend({ da.pitch_type, "Off", true })
  da.pitch_offset_randomize:depend({ da.pitch_type, "Off", true })
  da.pitch_speed:depend({ da.pitch_type, "Pendulum" })

  Class.ui.menu.footer = {
    title = defensive_aa_group:label("\aA0A0A0FF~ afterglow.yaw\r"),
    credits = defensive_aa_group:label("\aA0A0A0FFcrafted by lenora • 2026\r"),
  }
  local tab = Class.ui._custom_tab or Class.ui._ag_tab
  if tab then pcall(function() tab:adopt_remaining(10, 2) end) end
end

-- AA Additional > Exploits card (native category 11)
do
  local exploits_group = pui.group("lua", "b")
  Class.ui.menu.antiaim_tab.additional.exploits = {
    extended_yaw = exploits_group:checkbox(pui.macros.dot .. " Extended Yaw Bypass"),
    bind = exploits_group:hotkey(pui.macros.dot_accent .. " Extended Yaw Bind"),
    inverter = exploits_group:hotkey(pui.macros.dot_accent .. " Extended Inverter"),
    manual_left = exploits_group:hotkey(pui.macros.dot_accent .. " Extended Left"),
    manual_right = exploits_group:hotkey(pui.macros.dot_accent .. " Extended Right"),
    yaw_offset = exploits_group:slider(pui.macros.dot_accent .. " Extended Yaw Offset", 0, 180, 120, true, "\194\176"),
    pitch_mode = exploits_group:combobox(pui.macros.dot_accent .. " Extended Pitch", "Down", "Up", "Custom", "Random", "Disabled"),
    pitch_value = exploits_group:slider(pui.macros.dot_accent .. " Pitch Value", -89, 89, 89, true, "\194\176"),
    defensive = exploits_group:checkbox(pui.macros.dot .. " Extended Defensive"),
    defensive_ticks = exploits_group:slider(pui.macros.dot_accent .. " Defensive Choke", 1, 22, 16, true),
    flick = exploits_group:checkbox(pui.macros.dot .. " Flick Exploit"),
    flick_states = exploits_group:multiselect(pui.macros.dot_accent .. " Flick States", { "Standing", "Slow Walk", "Air", "Air-Crouch", "Crouch", "Move-Crouch" }),
    flick_pitch = exploits_group:combobox(pui.macros.dot_accent .. " Flick Pitch", "Off", "Static", "Sway", "Switch", "Random", "Static Random"),
    flick_pitch_1 = exploits_group:slider(pui.macros.dot_accent .. " Flick Pitch From", -89, 89, 0, true, "\194\176"),
    flick_pitch_2 = exploits_group:slider(pui.macros.dot_accent .. " Flick Pitch To", -89, 89, 0, true, "\194\176"),
    flick_speed = exploits_group:slider(pui.macros.dot_accent .. " Flick Speed", -75, 75, 20, true),
  }
  local ex = Class.ui.menu.antiaim_tab.additional.exploits
  ex.extended_yaw:depend(antiaim_tab_active, antiaim_tab_additional_active)
  ex.bind:depend(antiaim_tab_active, antiaim_tab_additional_active)
  for _, control in ipairs({ ex.inverter, ex.manual_left, ex.manual_right, ex.yaw_offset, ex.pitch_mode, ex.pitch_value, ex.defensive, ex.defensive_ticks }) do
    control:depend({ex.extended_yaw, true}, antiaim_tab_active, antiaim_tab_additional_active)
  end
  ex.pitch_value:depend({ex.pitch_mode, "Custom"})
  ex.defensive_ticks:depend({ex.defensive, true})
  -- Flick exploit is independent of Extended Yaw: gated only by the AA tab + its own checkbox.
  ex.flick:depend(antiaim_tab_active, antiaim_tab_additional_active)
  for _, control in ipairs({ ex.flick_states, ex.flick_pitch }) do
    control:depend({ex.flick, true}, antiaim_tab_active, antiaim_tab_additional_active)
  end
  ex.flick_pitch_1:depend({ex.flick, true}, {ex.flick_pitch, "Off", true})
  ex.flick_pitch_2:depend({ex.flick, true}, {ex.flick_pitch, "Off", true})
  ex.flick_speed:depend({ex.flick, true}, {ex.flick_pitch, "Sway"})
  local tab = Class.ui._custom_tab or Class.ui._ag_tab
  if tab then pcall(function() tab:adopt_remaining(11, 2) end) end
end

local add = Class.ui.menu.antiaim_tab.additional.extra
add.safe_head_enabled:depend(antiaim_tab_active, antiaim_tab_additional_active)
add.safe_head.conditions:depend({add.safe_head_enabled, true}, antiaim_tab_active, antiaim_tab_additional_active)
add.safe_head.height_difference:depend({add.safe_head_enabled, true}, {add.safe_head.conditions, "Above enemy"}, antiaim_tab_active, antiaim_tab_additional_active)
add.fast_ladder_enabled:depend(antiaim_tab_active, antiaim_tab_additional_active)
add.fast_ladder_avoid:depend({add.fast_ladder_enabled, true}, antiaim_tab_active, antiaim_tab_additional_active)
add.avoid_backstab_enabled:depend(antiaim_tab_active, antiaim_tab_additional_active)
add.avoid_backstab.amount:depend({add.avoid_backstab_enabled, true}, antiaim_tab_active, antiaim_tab_additional_active)
add.warmup.enabled:depend(antiaim_tab_active, antiaim_tab_additional_active)
add.warmup.triggers:depend({add.warmup.enabled, true}, antiaim_tab_active, antiaim_tab_additional_active)
for _, element in ipairs({ add.warmup.pitch, add.warmup.yaw_mode, add.warmup.range, add.warmup.speed }) do
  element:depend({add.warmup.enabled, true}, antiaim_tab_active, antiaim_tab_additional_active)
end
Class.ui.menu.visuals_tab.other.watermark.default.color:depend({Class.ui.menu.visuals_tab.other.watermark.color_mode, "Default"}, visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.gradient.color.prefix:depend(visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.gradient.color.postfix:depend(visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.gradient.color.inner:depend({Class.ui.menu.visuals_tab.other.watermark.color_mode, "Gradient"}, visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.gradient.color.outer:depend({Class.ui.menu.visuals_tab.other.watermark.color_mode, "Gradient"}, visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.gradient.direction:depend({Class.ui.menu.visuals_tab.other.watermark.color_mode, "Gradient"}, visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.rainbow.direction:depend({Class.ui.menu.visuals_tab.other.watermark.color_mode, "Rainbow"}, visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.font:depend(visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.color_mode:depend(visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.effect:depend(visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.pulse_speed:depend({Class.ui.menu.visuals_tab.other.watermark.effect, "Pulse"}, visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.gradient.speed:depend({Class.ui.menu.visuals_tab.other.watermark.color_mode, "Gradient"}, visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.rainbow.speed:depend({Class.ui.menu.visuals_tab.other.watermark.color_mode, "Rainbow"}, visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.rainbow.saturation:depend({Class.ui.menu.visuals_tab.other.watermark.color_mode, "Rainbow"}, visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.text:depend(visuals_tab_active)
Class.ui.menu.visuals_tab.other.watermark.icons_page:depend(visuals_tab_active)
if Class.ui.menu.visuals_tab.other.watermark.guide and Class.ui.menu.visuals_tab.other.watermark.guide.depend then Class.ui.menu.visuals_tab.other.watermark.guide:depend(visuals_tab_active) end
Class.ui.menu.visuals_tab.interface.velocity_indicator.enabled:depend(visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.velocity_indicator.color:depend({Class.ui.menu.visuals_tab.interface.velocity_indicator.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
local ma = Class.ui.menu.visuals_tab.interface.manual_arrows
ma.enabled:depend(visuals_tab_active, visuals_tab_interface_active)
ma.style:depend({ma.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
ma.yaw_color:depend({ma.enabled, true}, {ma.style, "Team Skeet"}, visuals_tab_active, visuals_tab_interface_active)
ma.body_color:depend({ma.enabled, true}, {ma.style, "Team Skeet"}, visuals_tab_active, visuals_tab_interface_active)
ma.custom_color:depend({ma.enabled, true}, {ma.style, "Custom", "CS2", "Modern"}, visuals_tab_active, visuals_tab_interface_active)
ma.cs2_idle_color:depend({ma.enabled, true}, {ma.style, "CS2"}, visuals_tab_active, visuals_tab_interface_active)
ma.offset:depend({ma.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
ma.font:depend({ma.enabled, true}, {ma.style, "Custom"}, visuals_tab_active, visuals_tab_interface_active)
ma.left:depend({ma.enabled, true}, {ma.style, "Custom"}, visuals_tab_active, visuals_tab_interface_active)
ma.right:depend({ma.enabled, true}, {ma.style, "Custom"}, visuals_tab_active, visuals_tab_interface_active)
ma.forward:depend({ma.enabled, true}, {ma.style, "Custom"}, visuals_tab_active, visuals_tab_interface_active)
local ci = Class.ui.menu.visuals_tab.interface.crosshair_indicator
ci.enabled:depend(visuals_tab_active, visuals_tab_interface_active)
ci.mode:depend({ci.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
-- Color Mode removed from UI; title halves follow AA body side (team-skeet style).
pcall(function()
  if ci.runes_color_mode.set_visible then
    ci.runes_color_mode:set_visible(false)
  elseif ci.runes_color_mode.ref then
    ui.set_visible(ci.runes_color_mode.ref, false)
  end
end)
ci.options:depend({ci.enabled, true}, {ci.mode, "Default"}, visuals_tab_active, visuals_tab_interface_active)
ci.direction:depend({ci.enabled, true}, {ci.mode, "Default"}, visuals_tab_active, visuals_tab_interface_active)
ci.gap_y:depend({ci.enabled, true}, {ci.mode, "Default"}, visuals_tab_active, visuals_tab_interface_active)
ci.color:depend({ci.enabled, true}, {ci.mode, "Default"}, visuals_tab_active, visuals_tab_interface_active)

Class.ui.menu.visuals_tab.interface.custom_scope.enabled:depend(visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.custom_scope.color:depend({Class.ui.menu.visuals_tab.interface.custom_scope.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.custom_scope.mode:depend({Class.ui.menu.visuals_tab.interface.custom_scope.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.custom_scope.offset.length:depend({Class.ui.menu.visuals_tab.interface.custom_scope.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.custom_scope.offset.gap:depend({Class.ui.menu.visuals_tab.interface.custom_scope.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.custom_scope.appear_speed:depend({Class.ui.menu.visuals_tab.interface.custom_scope.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.custom_scope.animate:depend({Class.ui.menu.visuals_tab.interface.custom_scope.enabled, true}, {Class.ui.menu.visuals_tab.interface.custom_scope.mode, "Rotated"}, visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.custom_scope.reversed:depend({Class.ui.menu.visuals_tab.interface.custom_scope.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.damage_indicator.enabled:depend(visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.damage_indicator.only_if_active:depend({Class.ui.menu.visuals_tab.interface.damage_indicator.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.damage_indicator.font:depend({Class.ui.menu.visuals_tab.interface.damage_indicator.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.damage_indicator.inactive_color:depend({Class.ui.menu.visuals_tab.interface.damage_indicator.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
Class.ui.menu.visuals_tab.interface.damage_indicator.active_color:depend({Class.ui.menu.visuals_tab.interface.damage_indicator.enabled, true}, visuals_tab_active, visuals_tab_interface_active)
local notifications = Class.ui.menu.visuals_tab.other.notifications
-- Notification settings belong to the Visuals/Other group, but must stay visible
-- while either Visuals sub-tab (Interface or Other) is selected.
-- notification depends applied after Side mount

Class.ui.menu.visuals_tab.other.zoom_animation.enabled:depend(visuals_tab_active, visuals_tab_other_active)
Class.ui.menu.visuals_tab.other.zoom_animation.speed:depend({Class.ui.menu.visuals_tab.other.zoom_animation.enabled, true}, visuals_tab_active, visuals_tab_other_active)

Class.ui.menu.visuals_tab.other.aspect_ratio.enabled:depend(visuals_tab_active, visuals_tab_other_active)
Class.ui.menu.visuals_tab.other.aspect_ratio.preset:depend(visuals_tab_active, visuals_tab_other_active)
Class.ui.menu.visuals_tab.other.aspect_ratio.amount:depend({Class.ui.menu.visuals_tab.other.aspect_ratio.enabled, true}, {Class.ui.menu.visuals_tab.other.aspect_ratio.preset, "Custom"}, visuals_tab_active, visuals_tab_other_active)
Class.ui.menu.visuals_tab.other.viewmodel_changer.enabled:depend(visuals_tab_active, visuals_tab_other_active)
Class.ui.menu.visuals_tab.other.viewmodel_changer.fov:depend({Class.ui.menu.visuals_tab.other.viewmodel_changer.enabled, true}, visuals_tab_active, visuals_tab_other_active)
Class.ui.menu.visuals_tab.other.viewmodel_changer.position.x:depend({Class.ui.menu.visuals_tab.other.viewmodel_changer.enabled, true}, visuals_tab_active, visuals_tab_other_active)
Class.ui.menu.visuals_tab.other.viewmodel_changer.position.y:depend({Class.ui.menu.visuals_tab.other.viewmodel_changer.enabled, true}, visuals_tab_active, visuals_tab_other_active)
Class.ui.menu.visuals_tab.other.viewmodel_changer.position.z:depend({Class.ui.menu.visuals_tab.other.viewmodel_changer.enabled, true}, visuals_tab_active, visuals_tab_other_active)
Class.ui.menu.visuals_tab.other.viewmodel_changer.features:depend({Class.ui.menu.visuals_tab.other.viewmodel_changer.enabled, true}, visuals_tab_active, visuals_tab_other_active)
-- Do not force Animation Breaker selections on startup; respect saved/empty states.
Class.ui.menu.misc_tab.animation_breaker.enabled:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.triggers:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.air.mode:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Air"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.ground.mode:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Legs"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.ground.static_delta:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Legs"}, {Class.ui.menu.misc_tab.animation_breaker.ground.mode, "Static"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.ground.delta_from:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Legs"}, {Class.ui.menu.misc_tab.animation_breaker.ground.mode, "Jitter"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.ground.delta_to:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Legs"}, {Class.ui.menu.misc_tab.animation_breaker.ground.mode, "Jitter"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.ground.jitter_delay:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Legs"}, {Class.ui.menu.misc_tab.animation_breaker.ground.mode, "Jitter"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.other.mode:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Other"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.other.body_lean:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Other"}, {Class.ui.menu.misc_tab.animation_breaker.other.mode, "Body Lean"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.other.allow_standing_leaning:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Other"}, {Class.ui.menu.misc_tab.animation_breaker.other.mode, "Body Lean"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.other.earthshake_strength:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Other"}, {Class.ui.menu.misc_tab.animation_breaker.other.mode, "Earthshake"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.other.leg_movement:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Other"}, {Class.ui.menu.misc_tab.animation_breaker.other.mode, "Leg movement"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.animation_breaker.other.walking_legs:depend({Class.ui.menu.misc_tab.animation_breaker.enabled, true}, {Class.ui.menu.misc_tab.animation_breaker.triggers, "Other"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.event_logger.force_teammate_aimbot.enabled:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.event_logger.force_teammate_aimbot.enemy_chat_viewer:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.trash_talk.enabled:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.trash_talk.mode:depend({Class.ui.menu.misc_tab.trash_talk.enabled, true}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.trash_talk.spectator_bait:depend({Class.ui.menu.misc_tab.trash_talk.enabled, true}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.trash_talk.bait_triggers:depend({Class.ui.menu.misc_tab.trash_talk.enabled, true}, {Class.ui.menu.misc_tab.trash_talk.mode, "Bait"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.trash_talk.triggers:depend({Class.ui.menu.misc_tab.trash_talk.enabled, true}, {Class.ui.menu.misc_tab.trash_talk.mode, "Author"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.trash_talk.delay:depend({Class.ui.menu.misc_tab.trash_talk.enabled, true}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.trash_talk.interval:depend({Class.ui.menu.misc_tab.trash_talk.enabled, true}, {Class.ui.menu.misc_tab.trash_talk.mode, "Author"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.event_logger.enabled:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.event_logger.triggers.event_triggers:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.event_logger.color.hit_purchase_color:depend({Class.ui.menu.misc_tab.event_logger.enabled, true}, {Class.ui.menu.misc_tab.event_logger.triggers.event_triggers, "Aimbot", "Purchase"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.event_logger.color.miss_connection_color:depend({Class.ui.menu.misc_tab.event_logger.enabled, true}, {Class.ui.menu.misc_tab.event_logger.triggers.event_triggers, "Aimbot", "Connection problems"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.event_logger.prefix:depend({Class.ui.menu.misc_tab.event_logger.enabled, true}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.event_logger.guide:depend({Class.ui.menu.misc_tab.event_logger.enabled, true}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.console_enhancement.mode:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.clan_tag.enabled:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.discord_rpc:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.optimize_cvars.enabled:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.optimize_cvars.mode:depend({Class.ui.menu.misc_tab.optimize_cvars.enabled, true}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.optimize_cvars.flags:depend({Class.ui.menu.misc_tab.optimize_cvars.enabled, true}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.optimize_cvars.options:depend({Class.ui.menu.misc_tab.optimize_cvars.enabled, true}, {Class.ui.menu.misc_tab.optimize_cvars.mode, "Custom"}, misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.addons:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.misc_tab.warmup_setup:depend(misc_tab_active, misc_subtab_active)
Class.ui.menu.config_tab.name:depend(config_tab_active)
Class.ui.menu.config_tab.load_sections:depend(config_tab_active)
Class.ui.menu.config_tab.create:depend(config_tab_active)
Class.ui.menu.config_tab.list:depend(config_tab_active)
Class.ui.menu.config_tab.cloud_info:depend({Class.ui.menu.config_tab.config_systems, "Cloud"}, config_tab_active)
Class.ui.menu.config_tab.save:depend(config_tab_active)
Class.ui.menu.config_tab.load:depend(config_tab_active)
Class.ui.menu.config_tab.delete:depend(config_tab_active)
Class.ui.menu.config_tab.import:depend({Class.ui.menu.config_tab.config_systems, "Local"}, config_tab_active)
Class.ui.menu.config_tab.export:depend({Class.ui.menu.config_tab.config_systems, "Local"}, config_tab_active)
Class.ui.menu.config_tab.cloud_view:depend({Class.ui.menu.config_tab.config_systems, "Cloud"}, config_tab_active)
Class.ui.menu.config_tab.cloud_visibility:depend({Class.ui.menu.config_tab.config_systems, "Cloud"}, {Class.ui.menu.config_tab.cloud_view, "My configs"}, config_tab_active)
Class.ui.menu.config_tab.cloud_refresh:depend({Class.ui.menu.config_tab.config_systems, "Cloud"}, config_tab_active)
Class.ui.menu.config_tab.cloud_favorite:depend({Class.ui.menu.config_tab.config_systems, "Cloud"}, config_tab_active)
Class.ui.menu.config_tab.cloud_like:depend({Class.ui.menu.config_tab.config_systems, "Cloud"}, config_tab_active)
Class.ui.menu.config_tab.cloud_dislike:depend({Class.ui.menu.config_tab.config_systems, "Cloud"}, config_tab_active)
Class.ui.menu.config_tab.config_systems:depend(home_panel_active)
-- Config Systems selects the backend used by the existing Config buttons.
Class.ui.menu.config_tab.config_systems:set_callback(function()
  local systems = Class.ui.menu.config_tab.config_systems
  if systems:get() == "Cloud" then
    if Class.config and Class.config.refresh_cloud_list then
      Class.config:refresh_cloud_list(false)
    end
  else
    if Class.config then
      Class.config.cloud_names = nil
      Class.config.cloud_metadata = nil
      pcall(function() Class.config:_refresh_list() end)
    end
  end
end)
-- Switching cloud views immediately fetches the selected collection.
-- Clear the previous collection first so rows from another view are never shown
-- while the new request is in flight.
Class.ui.menu.config_tab.cloud_view:set_callback(function()
  local config = Class.config
  if config and type(config.refresh_cloud_list) == "function" then
    config.cloud_visible_items = {}
    pcall(config._refresh_list, config)
    config:refresh_cloud_list(false)
  end
end)
pcall(function()
  Class.config.package = pui.setup(Class.ui.menu)
  Class.config.package_t = pui.setup(Class.ui.antiaim_conditions_t)
  Class.config.package_ct = pui.setup(Class.ui.antiaim_conditions_ct)
  pcall(function()
    local selection = Class.ui.menu.config_tab.load_sections
    if selection then selection:set({"GameSense Settings", "Anti-Aim", "Visuals", "Misc"}) end
  end)
  Class.config:_restore_ui_autosave()
  apply_username()
  local saved_watermark = Class.ui.menu.visuals_tab.other.watermark.text
  if saved_watermark then
    local saved_text = tostring(saved_watermark:get() or "")
    if saved_text == "G0TH$EH$E" or saved_text == "afterglow.yaw" then
      saved_watermark:set("afterglow")
    end
  end
  -- Manual arrow symbols keep textbox defaults / saved cfg values.
  -- Do not force-set them on load or user text gets wiped every reload.
  Class.util.text_state:bind()
  if Class.util.viewmodel_store and Class.util.viewmodel_store.hook then
    Class.util.viewmodel_store:hook()
  end
end)

pcall(ffi.cdef, [[
    typedef struct { int x; int y; } gothsense_inline_vec2_t;
    typedef struct { float r, g, b, a; } gothsense_inline_vec_color_t;
    typedef struct {
        void* begin;
        void* finish;
        void* capacity_end;
    } gothsense_inline_skeetvec_t;
    typedef struct {
        bool Editable;
        bool Visible;
        bool Hovered;
        bool AllowMouseInput;
        bool SameLine;
    } gothsense_inline_flags_t;
    typedef struct {
        void* pelement_link;
        char pad[0x18];
    } gothsense_inline_element_link_t;
    typedef struct {
        uint8_t pad1[0x14];
        gothsense_inline_flags_t Flags;
    } gothsense_inline_ui_base_t;
    typedef struct {
        char uiBaseData[0x20];
        gothsense_inline_vec2_t pos;
        gothsense_inline_vec2_t size;
        gothsense_inline_vec2_t thirdpos;
    } gothsense_inline_default_element_t;
    typedef struct {
        char _header[0x20];
        gothsense_inline_vec2_t pos;
        gothsense_inline_vec2_t InnerPadding;
        gothsense_inline_vec2_t OuterPadding;
        void* Name;
        gothsense_inline_skeetvec_t Calls;
        char pad2[0x4];
        gothsense_inline_vec_color_t Color;
        gothsense_inline_vec2_t BoxPos;
        uint32_t Value;
        int DefHeight;
        int Height;
        int DefInteractOffset;
        int InteractOffset;
        bool Open;
        bool Clicked;
        char pad3[0x2];
        int HoveredItem;
        int SelectedItem;
    } gothsense_inline_combo_element_t;
]])

local event_logger_inline_dpi
pcall(function()
    event_logger_inline_dpi = ui.reference("MISC", "Settings", "DPI scale")
end)

local function event_logger_inline_scale()
    local dpi_string = "100%"
    pcall(function()
        dpi_string = tostring(ui.get(event_logger_inline_dpi) or "100%")
    end)
    local percent = tonumber(dpi_string:match("(%d+)")) or 100
    return math.max(0.5, math.min(3, percent / 100))
end

local function event_logger_inline_native_ref(control)
    if control == nil then return nil end

    local direct
    pcall(function() direct = tonumber(control) end)
    if direct ~= nil and direct >= 0 then return math.floor(direct) end

    local candidates = {}
    local function add(value)
        if value == nil then return end
        candidates[#candidates + 1] = value
        if type(value) == "table" then
            local first
            pcall(function() first = value[1] end)
            if first ~= nil then candidates[#candidates + 1] = first end
            for _, key in ipairs({"ref", "reference", "handle", "id"}) do
                local nested
                pcall(function() nested = value[key] end)
                if nested ~= nil then candidates[#candidates + 1] = nested end
            end
        end
    end

    pcall(function() add(control.ref) end)
    pcall(function() add(control.reference) end)
    pcall(function() add(control.handle) end)
    pcall(function() add(control.id) end)
    if type(control) == "table" then
        local first
        pcall(function() first = control[1] end)
        if first ~= nil then add(first) end
    end

    for i = 1, #candidates do
        local index
        pcall(function() index = tonumber(candidates[i]) end)
        if index ~= nil then
            index = math.floor(index)
            if index >= 0 then return index end
        end
    end
    return nil
end

local function align_event_logger_controls()
    if not ui.is_menu_open() then return end

    pcall(function()
        local logger = Class.ui.menu.misc_tab.event_logger
        local checkbox_index = event_logger_inline_native_ref(logger.enabled)
        local multiselect_index = event_logger_inline_native_ref(logger.triggers.event_triggers)
        local hit_color_index = event_logger_inline_native_ref(logger.color.hit_purchase_color)
        local miss_color_index = event_logger_inline_native_ref(logger.color.miss_connection_color)
        if checkbox_index == nil or multiselect_index == nil or hit_color_index == nil or miss_color_index == nil then
            return
        end

        local elements = ffi.cast("gothsense_inline_skeetvec_t*", 1128765280)
        if elements == nil or elements.begin == nil or elements.finish == nil or elements.begin == elements.finish then
            return
        end

        local begin_address = tonumber(ffi.cast("uintptr_t", elements.begin))
        local finish_address = tonumber(ffi.cast("uintptr_t", elements.finish))
        if not begin_address or not finish_address or finish_address <= begin_address then return end

        local element_size = ffi.sizeof("gothsense_inline_element_link_t")
        local count = math.floor((finish_address - begin_address) / element_size)
        if count <= 0 or checkbox_index >= count or multiselect_index >= count or hit_color_index >= count or miss_color_index >= count then
            return
        end

        local links = ffi.cast("gothsense_inline_element_link_t*", elements.begin)
        local checkbox_link = links[checkbox_index].pelement_link
        local multiselect_link = links[multiselect_index].pelement_link
        local hit_color_link = links[hit_color_index].pelement_link
        local miss_color_link = links[miss_color_index].pelement_link
        if checkbox_link == nil or multiselect_link == nil or hit_color_link == nil or miss_color_link == nil then
            return
        end

        local multiselect_base = ffi.cast("gothsense_inline_ui_base_t*", multiselect_link)
        local checkbox_element = ffi.cast("gothsense_inline_default_element_t*", checkbox_link)
        local multiselect_element = ffi.cast("gothsense_inline_combo_element_t*", multiselect_link)
        local hit_color_element = ffi.cast("gothsense_inline_default_element_t*", hit_color_link)
        local miss_color_element = ffi.cast("gothsense_inline_default_element_t*", miss_color_link)

        local scale = event_logger_inline_scale()
        local label_width = math.floor(98 * scale)
        local color_gap = math.floor(20 * scale)

        multiselect_base.Flags.SameLine = true
        checkbox_element.size.x = label_width
        multiselect_element.pos.x = checkbox_element.pos.x + label_width
        multiselect_element.pos.y = checkbox_element.pos.y - math.floor(3 * scale)
        multiselect_element.Height = math.floor(18 * scale)

        -- Preserve the original trigger selector width; only align picker height with the checkbox.
        local color_row_y = checkbox_element.pos.y
        hit_color_element.pos.y = color_row_y
        miss_color_element.pos.y = color_row_y
        miss_color_element.pos.x = hit_color_element.pos.x - color_gap

        -- Event Logger multiselect width is assigned by the shared responsive combo layout below.
    end)
end

local inline_menu_layout_state = {
    rows = {},
    retry_categories = {},
    scale = nil,
}

local function align_visuals_and_config()
    if not ui.is_menu_open() then return end

    pcall(function()
        local reflow_categories = {}
        local function request_reflow(category_index)
            if category_index ~= nil then
                reflow_categories[category_index] = true
            end
        end
        local elements = ffi.cast("gothsense_inline_skeetvec_t*", 1128765280)
        if elements == nil or elements.begin == nil or elements.finish == nil or elements.begin == elements.finish then
            return
        end

        local begin_address = tonumber(ffi.cast("uintptr_t", elements.begin))
        local finish_address = tonumber(ffi.cast("uintptr_t", elements.finish))
        if not begin_address or not finish_address or finish_address <= begin_address then
            return
        end

        local element_size = ffi.sizeof("gothsense_inline_element_link_t")
        local count = math.floor((finish_address - begin_address) / element_size)
        if count <= 0 then
            return
        end
        local links = ffi.cast("gothsense_inline_element_link_t*", elements.begin)

        local function get_element(control, element_type)
            local index = event_logger_inline_native_ref(control)
            if index == nil or index < 0 or index >= count then
                return nil
            end
            local link = links[index].pelement_link
            if link == nil then
                return nil
            end
            return ffi.cast(element_type .. "*", link)
        end

        local scale = event_logger_inline_scale()
        if inline_menu_layout_state.scale ~= scale then
            inline_menu_layout_state.scale = scale
            request_reflow(2)
            request_reflow(3)
        end

        local function scaled_pixels(value, minimum, maximum)
            local pixels = math.floor((tonumber(value) or 0) * scale + 0.5)
            if minimum ~= nil then pixels = math.max(minimum, pixels) end
            if maximum ~= nil then pixels = math.min(maximum, pixels) end
            return pixels
        end

        local function inline_checkbox_combo(layout_key, category_index, checkbox_control, combo_control,
                label_width_px, combo_width_px, max_right_x, combo_y_adjust_px)
            local checkbox_element = get_element(checkbox_control, "gothsense_inline_default_element_t")
            local checkbox_base = get_element(checkbox_control, "gothsense_inline_ui_base_t")
            local combo_element = get_element(combo_control, "gothsense_inline_combo_element_t")
            local combo_base = get_element(combo_control, "gothsense_inline_ui_base_t")
            if checkbox_element == nil or checkbox_base == nil or combo_element == nil or combo_base == nil then
                return nil
            end

            local visible = checkbox_base.Flags.Visible and combo_base.Flags.Visible and true or false
            local row_state = inline_menu_layout_state.rows[layout_key]
            if row_state == nil then
                row_state = { visible = visible }
                inline_menu_layout_state.rows[layout_key] = row_state
                if visible then request_reflow(category_index) end
            elseif row_state.visible ~= visible then
                row_state.visible = visible
                request_reflow(category_index)
            end

            if not visible then return checkbox_element end
            if not combo_base.Flags.SameLine then
                combo_base.Flags.SameLine = true
                request_reflow(category_index)
            end

            local checkbox_x = tonumber(checkbox_element.pos.x)
            local checkbox_y = tonumber(checkbox_element.pos.y)
            if checkbox_x == nil or checkbox_y == nil then return nil end

            local minimum_combo = scaled_pixels(52, 36, 156)
            local label_gap = scaled_pixels(3, 1, 9)
            local label_width = scaled_pixels(label_width_px, 48, 540)
            local combo_x = checkbox_x + label_width + label_gap
            local combo_width = scaled_pixels(combo_width_px, minimum_combo, 720)
            local right_edge = tonumber(max_right_x)

            if right_edge ~= nil and right_edge > combo_x then
                local available = math.floor(right_edge - combo_x)
                if available < minimum_combo then
                    local reduction = minimum_combo - available
                    local minimum_label = scaled_pixels(60, 42, 180)
                    local reduced_label = math.max(minimum_label, label_width - reduction)
                    if reduced_label < label_width then
                        label_width = reduced_label
                        combo_x = checkbox_x + label_width + label_gap
                        available = math.floor(right_edge - combo_x)
                    end
                end
                combo_width = math.max(minimum_combo, math.min(720, available))
            end

            local y_adjust = combo_y_adjust_px
            if y_adjust == nil then y_adjust = 3 end
            local combo_y = checkbox_y - scaled_pixels(y_adjust, 0, 24)
            local combo_height = scaled_pixels(18, 9, 54)

            if tonumber(checkbox_element.size.x) ~= label_width then
                checkbox_element.size.x = label_width
            end
            if tonumber(combo_element.pos.x) ~= combo_x then combo_element.pos.x = combo_x end
            if tonumber(combo_element.pos.y) ~= combo_y then combo_element.pos.y = combo_y end
            if tonumber(combo_element.Height) ~= combo_height then combo_element.Height = combo_height end
            if tonumber(combo_element.InnerPadding.x) ~= combo_width then
                combo_element.InnerPadding.x = combo_width
            end
            return checkbox_element
        end

        local visuals = Class.ui.menu.visuals_tab

        -- right edge taken from a real native slider on the same column
        local function measure_slider_right(slider_control)
            if slider_control == nil then return nil end
            local el = get_element(slider_control, "gothsense_inline_default_element_t")
            if el ~= nil then
                local x = tonumber(el.pos.x)
                local width = tonumber(el.size.x)
                if x ~= nil and width ~= nil and width > 0 then
                    return x + width
                end
            end
            local combo = get_element(slider_control, "gothsense_inline_combo_element_t")
            if combo ~= nil then
                local x = tonumber(combo.pos.x)
                local inner = tonumber(combo.InnerPadding.x) or 0
                local outer = tonumber(combo.OuterPadding.x) or 0
                local width = math.max(inner, outer)
                if x ~= nil and width > 0 then return x + width end
            end
            return nil
        end

        local function measure_rightmost(controls)
            local rightmost = nil
            for _, control in pairs(controls) do
                local edge = measure_slider_right(control)
                if edge ~= nil and (rightmost == nil or edge > rightmost) then
                    rightmost = edge
                end
            end
            return rightmost
        end

        if visuals and visuals.interface and visuals.interface.crosshair_indicator then
            local iface = visuals.interface
            local indicator = iface.crosshair_indicator
            local max_right = nil
            if iface.custom_scope and iface.custom_scope.offset and iface.custom_scope.offset.length then
                max_right = measure_slider_right(iface.custom_scope.offset.length)
            end
            if max_right == nil and iface.custom_scope and iface.custom_scope.mode then
                local mode_el = get_element(iface.custom_scope.mode, "gothsense_inline_combo_element_t")
                if mode_el ~= nil then max_right = mode_el.pos.x + mode_el.InnerPadding.x end
            end
            inline_checkbox_combo("crosshair_indicator", 2, indicator.enabled, indicator.mode, 142, 128, max_right, 1)
        end


        if visuals and visuals.other and visuals.other.aspect_ratio then
            local aspect = visuals.other.aspect_ratio
            local zoom = visuals.other.zoom_animation
            local max_right = measure_rightmost({ zoom and zoom.speed })
            -- combobox length matches Zoom Animation Speed slider above
            inline_checkbox_combo("aspect_ratio", 2, aspect.enabled, aspect.preset, 110, 120, max_right)
            -- leave amount slider native (original size / layout)
        end

        -- Event Logger: use the same responsive checkbox + multiselect layout as Animation Breaker.
        do
            local misc = Class.ui.menu.misc_tab
            local logger = misc and misc.event_logger
            if logger and logger.enabled and logger.triggers and logger.triggers.event_triggers then
                local max_right = nil
                -- Use the full-width Prefix field as the panel boundary, not the color pickers.
                local prefix_element = get_element(logger.prefix, "gothsense_inline_default_element_t")
                if prefix_element ~= nil then
                    local prefix_x = tonumber(prefix_element.pos.x) or 0
                    local prefix_width = tonumber(prefix_element.size.x) or 0
                    if prefix_width > 0 then
                        max_right = prefix_x + prefix_width
                    end
                end
                inline_checkbox_combo("event_logger", 3, logger.enabled, logger.triggers.event_triggers, 98, 128, max_right)
            end
        end

        -- Manual Arrows: make the style combobox responsive like Event Logger's selector.
        -- The right edge follows the Offset slider, so the combo expands/contracts with the panel.
        do
            local iface = visuals and visuals.interface
            local manual_arrows = iface and iface.manual_arrows
            if manual_arrows and manual_arrows.enabled and manual_arrows.style then
                local max_right = measure_slider_right(manual_arrows.offset)
                inline_checkbox_combo("manual_arrows", 2, manual_arrows.enabled, manual_arrows.style, 118, 128, max_right)
            end
        end

        -- Animation Breaker: keep its trigger multiselect on the checkbox row.
        do
            local misc = Class.ui.menu.misc_tab
            local breaker = misc and misc.animation_breaker
            if breaker and breaker.enabled and breaker.triggers then
                local max_right = nil
                local candidates = {
                    breaker.ground and breaker.ground.static_delta,
                    breaker.ground and breaker.ground.delta_to,
                    breaker.ground and breaker.ground.jitter_delay,
                    breaker.other and breaker.other.body_lean,
                    breaker.other and breaker.other.earthshake_strength,
                }
                for i = 1, #candidates do
                    local right = measure_slider_right(candidates[i])
                    if right ~= nil and (max_right == nil or right > max_right) then
                        max_right = right
                    end
                end
                inline_checkbox_combo("animation_breaker", 3, breaker.enabled, breaker.triggers, 132, 128, max_right)
            end
        end

        -- Warmup AA: checkbox + triggers multiselect, width tracks slider/column on resize
        do
            local extra = Class.ui.menu.antiaim_tab and Class.ui.menu.antiaim_tab.additional and Class.ui.menu.antiaim_tab.additional.extra
            local warmup = extra and extra.warmup
            if warmup and warmup.enabled and warmup.triggers then
                local max_right = nil
                if extra.avoid_backstab and extra.avoid_backstab.amount then
                    max_right = measure_slider_right(extra.avoid_backstab.amount)
                end
                if max_right == nil and extra.safe_head and extra.safe_head.height_difference then
                    max_right = measure_slider_right(extra.safe_head.height_difference)
                end
                if max_right == nil and warmup.range then
                    max_right = measure_slider_right(warmup.range)
                end
                if max_right == nil and warmup.speed then
                    max_right = measure_slider_right(warmup.speed)
                end
                -- Same native layout path as Aspect Ratio
                inline_checkbox_combo("warmup_aa", 2, warmup.enabled, warmup.triggers, 100, 130, max_right)
            end
        end

        local cfg = Class.ui.menu.config_tab
        if cfg then
            local list_element = get_element(cfg.list, "gothsense_inline_default_element_t")
            local cloud_info_element = get_element(cfg.cloud_info, "gothsense_inline_default_element_t")
            local cloud_info_base = get_element(cfg.cloud_info, "gothsense_inline_ui_base_t")
            local name_element = get_element(cfg.name, "gothsense_inline_default_element_t")
            local cloud_view_element = get_element(cfg.cloud_view, "gothsense_inline_combo_element_t")
            local cloud_view_base = get_element(cfg.cloud_view, "gothsense_inline_ui_base_t")
            local cloud_selected = false
            local cloud_view = "My configs"
            local home_active = false
            pcall(function()
                cloud_selected = cfg.config_systems and cfg.config_systems:get() == "Cloud"
                cloud_view = cfg.cloud_view and cfg.cloud_view:get() or "My configs"
                home_active = Class.ui.menu.home_tab.selected_tab.default:get() == MENU_ROUTES.root_home
            end)
            local my_cloud_configs = cloud_selected and cloud_view == "My configs"
            local function set_control_visible(control, visible)
                local base = get_element(control, "gothsense_inline_ui_base_t")
                if base ~= nil then base.Flags.Visible = visible and true or false end
            end
            -- Cloud views have different action rows: management controls belong to My configs,
            -- while voting/favorite controls belong to the public collections.
            set_control_visible(cfg.create, home_active and (not cloud_selected or my_cloud_configs))
            set_control_visible(cfg.load, home_active)
            set_control_visible(cfg.load_sections, home_active)
            set_control_visible(cfg.save, home_active and (not cloud_selected or my_cloud_configs))
            set_control_visible(cfg.delete, home_active and (not cloud_selected or my_cloud_configs))
            set_control_visible(cfg.import, home_active and not cloud_selected)
            set_control_visible(cfg.export, home_active and not cloud_selected)
            local cloud_toolbar_visible = home_active and cloud_selected and not my_cloud_configs
            set_control_visible(cfg.cloud_dislike, cloud_toolbar_visible)
            set_control_visible(cfg.cloud_like, cloud_toolbar_visible)
            set_control_visible(cfg.cloud_refresh, cloud_toolbar_visible)
            set_control_visible(cfg.cloud_favorite, cloud_toolbar_visible)
            set_control_visible(cfg.cloud_visibility, home_active and my_cloud_configs)
            if list_element ~= nil then
                Class.ui._config_list_width = tonumber(list_element.size.x) or Class.ui._config_list_width
            end

            -- In Cloud mode keep the view selector directly above the list.
            -- Cloud action buttons are moved to their own compact row below Save/Delete.
            local cloud_gap = math.floor(5 * scale)
            if cloud_selected and list_element ~= nil and cloud_view_element ~= nil and cloud_view_base ~= nil then
                cloud_view_base.Flags.SameLine = false
                cloud_view_element.pos.x = list_element.pos.x
                cloud_view_element.Height = math.floor(18 * scale)
                cloud_view_element.InnerPadding.x = math.max(math.floor(48 * scale), tonumber(list_element.size.x) or 0)
                list_element.pos.y = cloud_view_element.pos.y + cloud_view_element.Height + cloud_gap
                if cloud_info_element ~= nil and cloud_info_base ~= nil then
                    cloud_info_base.Flags.SameLine = false
                    cloud_info_element.pos.x = list_element.pos.x
                    cloud_info_element.pos.y = list_element.pos.y + list_element.size.y + math.floor(2 * scale)
                    cloud_info_element.size.x = list_element.size.x
                    cloud_info_element.size.y = math.floor(15 * scale)
                end
                if name_element ~= nil then
                    name_element.pos.x = list_element.pos.x
                    if cloud_info_element ~= nil then
                        name_element.pos.y = cloud_info_element.pos.y + cloud_info_element.size.y + cloud_gap
                    else
                        name_element.pos.y = list_element.pos.y + list_element.size.y + cloud_gap
                    end
                    name_element.size.x = list_element.size.x
                end
                if my_cloud_configs and name_element ~= nil then
                    local visibility_element = get_element(cfg.cloud_visibility, "gothsense_inline_combo_element_t")
                    local visibility_base = get_element(cfg.cloud_visibility, "gothsense_inline_ui_base_t")
                    if visibility_element ~= nil and visibility_base ~= nil then
                        local selector_gap = math.floor(5 * scale)
                        local option_width = 0
                        for _, option in ipairs({ "Private", "Public" }) do
                            local measured = nil
                            pcall(function()
                                measured = select(1, renderer.measure_text("", option))
                            end)
                            measured = tonumber(measured)
                            if measured == nil or measured <= 0 then
                                measured = #option * 7 * scale
                            end
                            option_width = math.max(option_width, measured)
                        end
                        -- Fit the widest entry plus the native arrow and inner padding.
                        local selector_width = math.floor(option_width + 30 * scale + 0.5)
                        selector_width = math.max(math.floor(58 * scale), selector_width)
                        local full_name_width = tonumber(list_element and list_element.size.x) or tonumber(name_element.size.x) or 0
                        if full_name_width > 0 then
                            name_element.size.x = math.max(math.floor(72 * scale), full_name_width - selector_width - selector_gap)
                        end
                        visibility_base.Flags.SameLine = true
                        visibility_element.pos.x = name_element.pos.x + name_element.size.x + selector_gap
                        visibility_element.pos.y = name_element.pos.y - math.floor(3 * scale)
                        visibility_element.Height = math.floor(18 * scale)
                        visibility_element.InnerPadding.x = selector_width
                    end
                end
            end

            local rows = {
                {cfg.create, cfg.load},
                {cfg.save, cfg.delete},
                {cfg.import, cfg.export},
            }

            local total_width = nil
            local origin_x, origin_y

            -- grid width must match the textbox (preferred) or listbox width exactly
            if name_element ~= nil then
                origin_x = name_element.pos.x
                origin_y = name_element.pos.y + name_element.size.y + math.floor(2 * scale)
                total_width = list_element ~= nil and (tonumber(list_element.size.x) or name_element.size.x) or name_element.size.x
            end
            if (total_width == nil or total_width <= 0) and list_element ~= nil then
                origin_x = list_element.pos.x
                origin_y = list_element.pos.y + list_element.size.y + math.floor(2 * scale)
                total_width = list_element.size.x
            end

            if origin_x ~= nil and origin_y ~= nil and total_width ~= nil and total_width > 0 then
                local gap = math.floor(5 * scale)
                local button_width = math.floor((total_width - gap) / 2)

                -- Load Sections sits between the config name and action buttons.
                -- Its width follows the same live list / textbox width.
                local load_sections_element = get_element(cfg.load_sections, "gothsense_inline_combo_element_t")
                local load_sections_base = get_element(cfg.load_sections, "gothsense_inline_ui_base_t")
                if load_sections_element ~= nil and load_sections_base ~= nil then
                    load_sections_base.Flags.SameLine = false
                    load_sections_element.pos.x = origin_x
                    load_sections_element.pos.y = origin_y
                    load_sections_element.Height = math.floor(18 * scale)
                    load_sections_element.InnerPadding.x = total_width
                    origin_y = load_sections_element.pos.y + load_sections_element.Height + gap
                end

                local grid_visible, grid_bottom = false, nil
                for row = 1, #rows do
                    local left_control, right_control = rows[row][1], rows[row][2]
                    local left_element = get_element(left_control, "gothsense_inline_default_element_t")
                    local right_element = get_element(right_control, "gothsense_inline_default_element_t")
                    local left_base = get_element(left_control, "gothsense_inline_ui_base_t")
                    local right_base = get_element(right_control, "gothsense_inline_ui_base_t")
                    if left_element ~= nil and right_element ~= nil and left_base ~= nil and right_base ~= nil then
                        left_base.Flags.SameLine = false
                        right_base.Flags.SameLine = true
                        left_element.size.x = button_width
                        right_element.size.x = button_width
                        left_element.pos.x = origin_x
                        right_element.pos.x = origin_x + button_width + gap
                        -- vertical gap == horizontal gap between buttons
                        local button_height = left_element.size.y
                        if button_height <= 0 then
                            button_height = math.floor(18 * scale)
                        end
                        local y = origin_y + (row - 1) * (button_height + gap)
                        left_element.pos.y = y
                        right_element.pos.y = y
                        grid_visible = left_base.Flags.Visible
                        grid_bottom = y + button_height
                    end
                end

                if cloud_selected then
                    local cloud_buttons = {cfg.cloud_dislike, cfg.cloud_like, cfg.cloud_refresh, cfg.cloud_favorite}
                    local load_element = get_element(cfg.load, "gothsense_inline_default_element_t")
                    local load_base = get_element(cfg.load, "gothsense_inline_ui_base_t")
                    if not my_cloud_configs and load_element ~= nil and load_base ~= nil then
                        local button_height = tonumber(load_element.size.y) or math.floor(18 * scale)
                        if button_height <= 0 then button_height = math.floor(18 * scale) end
                        -- In Explore / Favorites / Liked, Load is the only standard action.
                        -- Center it as a full-width row instead of leaving gaps for hidden buttons.
                        load_base.Flags.SameLine = false
                        load_element.pos.x = origin_x
                        load_element.pos.y = origin_y
                        load_element.size.x = total_width
                        load_element.size.y = button_height
                        grid_visible = true
                        grid_bottom = origin_y + button_height

                        local y = grid_bottom + gap
                        local icon_gap = math.floor(4 * scale)
                        local icon_width = math.floor((total_width - icon_gap * (#cloud_buttons - 1)) / #cloud_buttons)
                        icon_width = math.max(math.floor(18 * scale), icon_width)
                        local any_visible = false
                        for i = 1, #cloud_buttons do
                            local button = cloud_buttons[i]
                            local element = get_element(button, "gothsense_inline_default_element_t")
                            local base = get_element(button, "gothsense_inline_ui_base_t")
                            if element ~= nil and base ~= nil then
                                base.Flags.SameLine = i > 1
                                element.pos.x = origin_x + (i - 1) * (icon_width + icon_gap)
                                element.pos.y = y
                                element.size.x = icon_width
                                element.size.y = button_height
                                any_visible = any_visible or base.Flags.Visible
                            end
                        end
                        if any_visible then
                            grid_visible = true
                            grid_bottom = y + button_height
                        end
                    end
                end

            end
        end

        for category_index in pairs(inline_menu_layout_state.retry_categories) do
            reflow_categories[category_index] = true
        end
        local tab = Class.ui._custom_tab or Class.ui._ag_tab
        for category_index in pairs(reflow_categories) do
            local reflowed = false
            if tab ~= nil and type(tab.reflow_category) == "function" then
                local ok, result = pcall(tab.reflow_category, tab, category_index)
                reflowed = ok and result ~= false
            end
            inline_menu_layout_state.retry_categories[category_index] = not reflowed or nil
        end

    end)
end


local function align_footer_to_menu_bottom_left()
    if not ui.is_menu_open() then return end

    local ok = pcall(function()
        local menu_ui = Class.ui and Class.ui.menu
        local footer = menu_ui and (menu_ui.footer_active or menu_ui.footer)
        if footer == nil then return end

        local elements = ffi.cast("gothsense_inline_skeetvec_t*", 1128765280)
        if elements == nil or elements.begin == nil or elements.finish == nil
            or elements.begin == elements.finish then
            return
        end

        local begin_address = tonumber(ffi.cast("uintptr_t", elements.begin))
        local finish_address = tonumber(ffi.cast("uintptr_t", elements.finish))
        if begin_address == nil or finish_address == nil or finish_address <= begin_address then return end

        local link_size = ffi.sizeof("gothsense_inline_element_link_t")
        local count = math.floor((finish_address - begin_address) / link_size)
        if count <= 0 then return end
        local links = ffi.cast("gothsense_inline_element_link_t*", elements.begin)

        local function get_link(control)
            local index = event_logger_inline_native_ref(control)
            if index == nil or index < 0 or index >= count then return nil, nil end
            local link = links[index].pelement_link
            if link == nil then return nil, nil end
            return link, index
        end

        local title_link, title_index = get_link(footer.title)
        local credits_link, credits_index = get_link(footer.credits)
        if title_link == nil or credits_link == nil then return end

        local title_el = ffi.cast("gothsense_inline_default_element_t*", title_link)
        local credits_el = ffi.cast("gothsense_inline_default_element_t*", credits_link)
        local title_base = ffi.cast("gothsense_inline_ui_base_t*", title_link)
        local credits_base = ffi.cast("gothsense_inline_ui_base_t*", credits_link)

        -- Every native control stores its owning category pointer at +0x10.
        -- Its height is at +0x2C, in the same coordinate system as child controls.
        local parent_address = tonumber(ffi.cast("uint32_t*", ffi.cast("uint8_t*", title_link) + 0x10)[0])
        local credits_parent = tonumber(ffi.cast("uint32_t*", ffi.cast("uint8_t*", credits_link) + 0x10)[0])
        if parent_address == nil or parent_address < 0x10000 or credits_parent ~= parent_address then return end

        local panel_height = tonumber(ffi.cast("int32_t*", parent_address + 0x2C)[0])
        local panel_width = tonumber(ffi.cast("int32_t*", parent_address + 0x28)[0])
        if panel_height == nil or panel_width == nil or panel_height < 80 or panel_height > 4096
            or panel_width < 80 or panel_width > 4096 then
            return
        end

        local scale = event_logger_inline_scale()
        local footer_gap = math.floor(8 * scale)
        local bottom_gap = math.floor(9 * scale)
        local line_gap = math.floor(2 * scale)
        local title_height = tonumber(title_el.size.y) or math.floor(14 * scale)
        local credits_height = tonumber(credits_el.size.y) or math.floor(14 * scale)
        if title_height <= 0 or title_height > 40 * scale then title_height = math.floor(14 * scale) end
        if credits_height <= 0 or credits_height > 40 * scale then credits_height = math.floor(14 * scale) end
        local footer_height = title_height + line_gap + credits_height

        local last_control_bottom = 0
        for i = 0, count - 1 do
            if i ~= title_index and i ~= credits_index then
                local link = links[i].pelement_link
                if link ~= nil then
                    local base = ffi.cast("gothsense_inline_ui_base_t*", link)
                    if base.Flags.Visible then
                        local owner = tonumber(ffi.cast("uint32_t*", ffi.cast("uint8_t*", link) + 0x10)[0])
                        if owner == parent_address then
                            local raw = ffi.cast("uint8_t*", link)
                            local y = tonumber(ffi.cast("int32_t*", raw + 0x24)[0])
                            local h = tonumber(ffi.cast("int32_t*", raw + 0x2C)[0]) or 0
                            -- Combo controls keep their height at +0x70; account for it
                            -- as well as the default element's size.y.
                            local combo_h = tonumber(ffi.cast("int32_t*", raw + 0x70)[0]) or 0
                            if combo_h >= math.floor(10 * scale) and combo_h <= math.floor(40 * scale) then
                                h = math.max(h, combo_h)
                            end
                            if h <= 0 or h > math.floor(300 * scale) then h = math.floor(18 * scale) end
                            if y ~= nil then last_control_bottom = math.max(last_control_bottom, y + h) end
                        end
                    end
                end
            end
        end

        -- Anchor the active credits to their owning left card (Core on non-builder routes,
        -- Defensive AA on the builder). Keep horizontal/bottom insets consistent with the panel.
        local side_gap = bottom_gap
        side_gap = math.min(side_gap, math.max(0, panel_width - math.floor(24 * scale)))

        local bottom_anchored_y = panel_height - bottom_gap - footer_height
        local safe_y = last_control_bottom + footer_gap
        local footer_y = math.max(bottom_anchored_y, safe_y)
        -- Never pull the footer back over a button: when the content reaches
        -- the panel's bottom, place it after the last visible sibling instead.
        if footer_y < 0 then return end

        title_base.Flags.Visible = true
        credits_base.Flags.Visible = true
        title_base.Flags.SameLine = false
        credits_base.Flags.SameLine = false
        title_el.pos.x = side_gap
        credits_el.pos.x = side_gap
        title_el.pos.y = math.floor(footer_y)
        credits_el.pos.y = math.floor(footer_y + title_height + line_gap)
    end)

    if not ok and not Class.ui._footer_native_error_logged then
        Class.ui._footer_native_error_logged = true
        client.log("[afterglow] native footer positioning failed")
    end
end

local function align_manual_arrows_controls()
    if not ui.is_menu_open() then return end

    pcall(function()
        local ma = Class.ui.menu.visuals_tab.interface.manual_arrows
        if not ma or not ma.enabled or not ma.style then return end

        local checkbox_index = event_logger_inline_native_ref(ma.enabled)
        local style_index = event_logger_inline_native_ref(ma.style)
        local selected_style = ma.style:get()
        local yaw_index = event_logger_inline_native_ref(selected_style == "Team Skeet" and ma.yaw_color or ma.custom_color)
        local body_index = event_logger_inline_native_ref(selected_style == "CS2" and ma.cs2_idle_color or ma.body_color)
        if checkbox_index == nil or style_index == nil then return end

        local elements = ffi.cast("gothsense_inline_skeetvec_t*", 1128765280)
        if elements == nil or elements.begin == nil or elements.finish == nil or elements.begin == elements.finish then
            return
        end

        local begin_address = tonumber(ffi.cast("uintptr_t", elements.begin))
        local finish_address = tonumber(ffi.cast("uintptr_t", elements.finish))
        if not begin_address or not finish_address or finish_address <= begin_address then return end

        local element_size = ffi.sizeof("gothsense_inline_element_link_t")
        local count = math.floor((finish_address - begin_address) / element_size)
        if count <= 0 or checkbox_index < 0 or style_index < 0 or checkbox_index >= count or style_index >= count then return end

        local links = ffi.cast("gothsense_inline_element_link_t*", elements.begin)
        local checkbox_link = links[checkbox_index].pelement_link
        local style_link = links[style_index].pelement_link
        if checkbox_link == nil or style_link == nil then return end

        local style_base = ffi.cast("gothsense_inline_ui_base_t*", style_link)
        local checkbox_element = ffi.cast("gothsense_inline_default_element_t*", checkbox_link)
        local style_element = ffi.cast("gothsense_inline_combo_element_t*", style_link)

        local scale = event_logger_inline_scale()
        local label_width = math.floor(118 * scale)

        -- Keep the existing checkbox + style row; do not force a custom combo width.
        style_base.Flags.SameLine = true
        checkbox_element.size.x = label_width
        style_element.pos.x = checkbox_element.pos.x + label_width
        style_element.pos.y = checkbox_element.pos.y - math.floor(3 * scale)
        style_element.Height = math.floor(18 * scale)

        -- Match Event Logger's native picker positioning exactly:
        -- preserve the first picker X, align both Y values to the checkbox,
        -- and place the second picker relative to the first.
        if yaw_index ~= nil and body_index ~= nil
            and yaw_index >= 0 and body_index >= 0
            and yaw_index < count and body_index < count then
            local yaw_link = links[yaw_index].pelement_link
            local body_link = links[body_index].pelement_link
            if yaw_link ~= nil and body_link ~= nil then
                local yaw_element = ffi.cast("gothsense_inline_default_element_t*", yaw_link)
                local body_element = ffi.cast("gothsense_inline_default_element_t*", body_link)
                local row_y = checkbox_element.pos.y
                local color_gap = math.floor(20 * scale)

                yaw_element.pos.y = row_y
                body_element.pos.y = row_y
                body_element.pos.x = yaw_element.pos.x - color_gap
            end
        end
    end)
end

local function align_extended_yaw_bind()
  if not ui.is_menu_open() then return end

  pcall(function()
    local exploits = Class.ui.menu.antiaim_tab.additional.exploits
    if not exploits or not exploits.extended_yaw or not exploits.bind then return end

    local checkbox_index = event_logger_inline_native_ref(exploits.extended_yaw)
    local bind_index = event_logger_inline_native_ref(exploits.bind)
    if checkbox_index == nil or bind_index == nil or checkbox_index == bind_index then return end

    local elements = ffi.cast("gothsense_inline_skeetvec_t*", 1128765280)
    if elements == nil or elements.begin == nil or elements.finish == nil
      or elements.begin == elements.finish then
      return
    end

    local begin_address = tonumber(ffi.cast("uintptr_t", elements.begin))
    local finish_address = tonumber(ffi.cast("uintptr_t", elements.finish))
    if not begin_address or not finish_address or finish_address <= begin_address then return end

    local element_size = ffi.sizeof("gothsense_inline_element_link_t")
    local count = math.floor((finish_address - begin_address) / element_size)
    if checkbox_index < 0 or bind_index < 0 or checkbox_index >= count or bind_index >= count then return end

    local links = ffi.cast("gothsense_inline_element_link_t*", elements.begin)
    local checkbox_link = links[checkbox_index].pelement_link
    local bind_link = links[bind_index].pelement_link
    if checkbox_link == nil or bind_link == nil then return end

    local checkbox_base = ffi.cast("gothsense_inline_ui_base_t*", checkbox_link)
    local bind_base = ffi.cast("gothsense_inline_ui_base_t*", bind_link)
    local checkbox_element = ffi.cast("gothsense_inline_default_element_t*", checkbox_link)
    local bind_element = ffi.cast("gothsense_inline_default_element_t*", bind_link)
    if not checkbox_base.Flags.Visible or not bind_base.Flags.Visible then return end

    local parent_address = tonumber(ffi.cast("uint32_t*", ffi.cast("uint8_t*", checkbox_link) + 0x10)[0])
    if parent_address == nil or parent_address < 0x10000 then return end
    local panel_width = tonumber(ffi.cast("int32_t*", parent_address + 0x28)[0]) or 0
    if panel_width < 100 or panel_width > 4096 then return end

    local scale = event_logger_inline_scale()
    local side_inset = math.floor(10 * scale)
    local gap = math.floor(6 * scale)
    local available_width = panel_width - side_inset * 2
    local checkbox_width = math.floor(150 * scale)
    local bind_width = available_width - checkbox_width - gap
    if bind_width < math.floor(88 * scale) then
      checkbox_width = math.floor(available_width * 0.52)
      bind_width = available_width - checkbox_width - gap
    end
    if checkbox_width <= 0 or bind_width <= 0 then return end

    checkbox_base.Flags.SameLine = false
    bind_base.Flags.SameLine = true
    checkbox_element.size.x = checkbox_width
    bind_element.size.x = bind_width
    bind_element.pos.x = checkbox_element.pos.x + checkbox_width + gap
    bind_element.pos.y = checkbox_element.pos.y
  end)
end

local function align_builder_action_buttons()
  if not ui.is_menu_open() then return end
  local rows = Class.ui and Class.ui._builder_action_rows
  if not rows or #rows == 0 then return end

  pcall(function()
    local elements = ffi.cast("gothsense_inline_skeetvec_t*", 1128765280)
    if elements == nil or elements.begin == nil or elements.finish == nil or elements.begin == elements.finish then
      return
    end
    local begin_address = tonumber(ffi.cast("uintptr_t", elements.begin))
    local finish_address = tonumber(ffi.cast("uintptr_t", elements.finish))
    if not begin_address or not finish_address or finish_address <= begin_address then
      return
    end
    local element_size = ffi.sizeof("gothsense_inline_element_link_t")
    local count = math.floor((finish_address - begin_address) / element_size)
    if count <= 0 then return end
    local links = ffi.cast("gothsense_inline_element_link_t*", elements.begin)

    local function get_element(control, element_type)
      local index = event_logger_inline_native_ref(control)
      if index == nil or index < 0 or index >= count then
        return nil
      end
      local link = links[index].pelement_link
      if link == nil then return nil end
      return ffi.cast(element_type .. "*", link)
    end

    local scale = event_logger_inline_scale()
    local gap = math.floor(5 * scale)

    for i = 1, #rows do
      local send_c, copy_c, paste_c = rows[i][1], rows[i][2], rows[i][3]
      local send_el = get_element(send_c, "gothsense_inline_default_element_t")
      local copy_el = get_element(copy_c, "gothsense_inline_default_element_t")
      local paste_el = get_element(paste_c, "gothsense_inline_default_element_t")
      local send_base = get_element(send_c, "gothsense_inline_ui_base_t")
      local copy_base = get_element(copy_c, "gothsense_inline_ui_base_t")
      local paste_base = get_element(paste_c, "gothsense_inline_ui_base_t")
      if send_el ~= nil and copy_el ~= nil and paste_el ~= nil
        and send_base ~= nil and copy_base ~= nil and paste_base ~= nil
        and send_base.Flags.Visible then
        local total_width = tonumber(send_el.size.x) or 0
        if total_width > 0 then
          local button_width = math.floor((total_width - gap) / 2)
          if button_width >= 8 then
            local origin_x = tonumber(send_el.pos.x) or 0
            local origin_y = (tonumber(send_el.pos.y) or 0) + (tonumber(send_el.size.y) or 18) + math.floor(2 * scale)
            copy_base.Flags.SameLine = false
            paste_base.Flags.SameLine = true
            copy_el.size.x = button_width
            paste_el.size.x = button_width
            copy_el.pos.x = origin_x
            paste_el.pos.x = origin_x + button_width + gap
            copy_el.pos.y = origin_y
            paste_el.pos.y = origin_y
          end
        end
      end
    end
  end)
end

local function align_root_nav_buttons()
  if not ui.is_menu_open() then return end

  pcall(function()
    local buttons = Class.ui and Class.ui._nav_tabs
    local sub_tabs = Class.ui and Class.ui._nav_sub
    if type(buttons) ~= "table" or #buttons < 4 or type(sub_tabs) ~= "table" then return end

    local elements = ffi.cast("gothsense_inline_skeetvec_t*", 1128765280)
    if elements == nil or elements.begin == nil or elements.finish == nil or elements.begin == elements.finish then
      return
    end

    local begin_address = tonumber(ffi.cast("uintptr_t", elements.begin))
    local finish_address = tonumber(ffi.cast("uintptr_t", elements.finish))
    if not begin_address or not finish_address or finish_address <= begin_address then return end

    local element_size = ffi.sizeof("gothsense_inline_element_link_t")
    local count = math.floor((finish_address - begin_address) / element_size)
    if count <= 0 then return end
    local links = ffi.cast("gothsense_inline_element_link_t*", elements.begin)

    local function get_link(control)
      local index = event_logger_inline_native_ref(control)
      if index == nil or index < 0 or index >= count then return nil end
      local link = links[index].pelement_link
      if link == nil then return nil end
      return link
    end

    local rows = {}
    for i = 1, 4 do
      local link = get_link(buttons[i])
      if link == nil then return end
      rows[i] = {
        base = ffi.cast("gothsense_inline_ui_base_t*", link),
        element = ffi.cast("gothsense_inline_default_element_t*", link),
      }
    end

    -- Anchor to the currently visible sub-combo. Hidden combos can retain stale
    -- coordinates after switching roots and pull the Navigate row out of place.
    local active_root = MENU_ROUTES.root_home
    pcall(function()
      active_root = Class.ui.menu.home_tab.selected_tab.default:get()
    end)
    local active_sub_key = active_root == MENU_ROUTES.root_antiaim and "aa"
      or active_root == MENU_ROUTES.root_visuals and "vis"
      or active_root == MENU_ROUTES.root_misc and "misc"
      or nil
    local reference_combo = active_sub_key and get_link(sub_tabs[active_sub_key]) or nil
    if reference_combo == nil then
      -- Home has no visible sub-combo; the hidden sub-combos are kept in sync
      -- below, so one of them is a safe geometry fallback there.
      reference_combo = get_link(sub_tabs.aa) or get_link(sub_tabs.vis) or get_link(sub_tabs.misc)
    end
    local combo_x, combo_width
    if reference_combo ~= nil then
      local combo = ffi.cast("gothsense_inline_combo_element_t*", reference_combo)
      combo_x = tonumber(combo.pos.x)
      combo_width = tonumber(combo.InnerPadding.x)
    end

    local first = rows[1].element
    local fallback_x = tonumber(first.pos.x) or 0
    local fallback_width = tonumber(first.size.x) or 0
    local layout = Class.ui._nav_tabs_layout
    if combo_width == nil or combo_width <= 0 then
      if type(layout) ~= "table" then
        if fallback_width <= 0 then return end
        layout = { x = fallback_x, width = fallback_width }
        Class.ui._nav_tabs_layout = layout
      end
      combo_x = combo_x or layout.x
      combo_width = tonumber(layout.width) or fallback_width
    else
      -- Keep the latest measured combo geometry; it follows menu resizing.
      Class.ui._nav_tabs_layout = { x = combo_x, width = combo_width }
    end

    local origin_x = combo_x or fallback_x
    local available_width = combo_width or fallback_width
    if available_width <= 0 then return end

    local scale = event_logger_inline_scale()
    local gap = math.floor(3 * scale)
    local button_width = math.floor((available_width - gap * 3) / 4)
    if button_width < math.floor(28 * scale) then return end

    local row_width = button_width * 4 + gap * 3
    local row_origin_x = origin_x + math.floor((available_width - row_width) / 2)
    local origin_y = tonumber(first.pos.y) or 0

    for i = 1, 4 do
      local row = rows[i]
      row.base.Flags.SameLine = i > 1
      row.element.size.x = button_width
      row.element.pos.x = row_origin_x + (i - 1) * (button_width + gap)
      row.element.pos.y = origin_y
    end

    -- Keep every section selector on one shared row beneath the four buttons.
    -- Only one selector is visible at a time; SameLine prevents the two hidden
    -- selectors from reserving extra blank rows and making Navigate scrollable.
    local row_bottom = origin_y + (tonumber(first.size.y) or 18) + math.floor(4 * scale)
    local sub_keys = { "aa", "vis", "misc" }
    for index, key in ipairs(sub_keys) do
      local link = get_link(sub_tabs[key])
      if link ~= nil then
        local base = ffi.cast("gothsense_inline_ui_base_t*", link)
        local combo = ffi.cast("gothsense_inline_combo_element_t*", link)
        base.Flags.SameLine = index > 1
        combo.pos.x = origin_x
        combo.pos.y = row_bottom
        combo.InnerPadding.x = available_width

      end
    end
  end)
end

Class.ui.align_footer_to_menu_bottom_left = align_footer_to_menu_bottom_left
Class.ui.align_event_logger_controls = align_event_logger_controls
Class.ui.align_manual_arrows_controls = align_manual_arrows_controls
Class.ui.align_extended_yaw_bind = align_extended_yaw_bind
Class.ui.align_visuals_and_config = align_visuals_and_config
Class.ui.align_builder_action_buttons = align_builder_action_buttons
Class.ui.align_root_nav_buttons = align_root_nav_buttons

end
do

do
  local named_pipes_ok, named_pipes = pcall(require, "gamesense/named_pipes")
  local OPCODE_HANDSHAKE, OPCODE_FRAME, OPCODE_CLOSE, OPCODE_PING, OPCODE_PONG = 0, 1, 2, 3, 4
  local DISCORD_CLIENT_ID = "1563196456163221640"

  local function pack_int32le(int)
    return ffi.string(ffi.cast("const char*", ffi.new("uint32_t[1]", int)), 4)
  end
  local function unpack_int32le(str)
    return tonumber(ffi.cast("uint32_t*", ffi.cast("const char*", str))[0])
  end
  local function encode_str(opcode, str)
    return pack_int32le(opcode) .. pack_int32le(#str) .. str
  end

  local function clean_mapname(name)
    name = tostring(name or ""):lower()
    name = name:gsub("^workshop/%d+/", "")
    name = name:gsub("%.bsp$", "")
    name = name:match("([^/\\]+)$") or name
    return name
  end

  local rpc = {
    pipe = nil,
    open = false,
    ready = false,
    last_activity = nil,
    last_update = 0,
    last_connect_try = 0,
    session_start = nil,
    last_signature = nil,
  }

  local function rpc_write(opcode, str)
    if not rpc.pipe then return false end
    local ok = pcall(function()
      rpc.pipe:write(encode_str(opcode, str))
    end)
    if not ok then
      pcall(function() if rpc.pipe and rpc.pipe.close then rpc.pipe:close() end end)
      rpc.pipe, rpc.open, rpc.ready = nil, false, false
      return false
    end
    return true
  end

  local function rpc_read()
    if not rpc.pipe then return end
    pcall(function()
      while true do
        local header = rpc.pipe:read(8)
        if header == nil or #header < 8 then break end
        local opcode = unpack_int32le(header:sub(1, 4))
        local len = unpack_int32le(header:sub(5, 8))
        if len < 0 or len > 65536 then break end
        local raw = rpc.pipe:read(len)
        if raw == nil then break end
        local data = nil
        pcall(function() data = json.parse(raw) end)
        if opcode == OPCODE_CLOSE then
          pcall(function() if rpc.pipe.close then rpc.pipe:close() end end)
          rpc.pipe, rpc.open, rpc.ready = nil, false, false
          break
        elseif opcode == OPCODE_PING then
          rpc_write(OPCODE_PONG, raw or "{}")
        elseif data and data.evt == "READY" then
          rpc.ready = true
        elseif data and data.cmd == "DISPATCH" and data.evt == "READY" then
          rpc.ready = true
        end
      end
    end)
  end

  local function rpc_connect()
    if not named_pipes_ok or not named_pipes then return false end
    if rpc.pipe then return true end
    local now = globals.realtime() or 0
    if now - (rpc.last_connect_try or 0) < 3 then return false end
    rpc.last_connect_try = now
    for i = 0, 9 do
      local ok, pipe = pcall(named_pipes.open_pipe, "\\\\?\\pipe\\discord-ipc-" .. i)
      if ok and pipe then
        rpc.pipe = pipe
        rpc.open = true
        rpc.ready = false
        rpc.last_signature = nil
        local payload = string.format('{"v":1,"client_id":"%s"}', DISCORD_CLIENT_ID)
        rpc_write(OPCODE_HANDSHAKE, payload)
        return true
      end
    end
    return false
  end

  local function rpc_set_activity(activity)
    if not rpc.ready then return end
    local payload = {
      cmd = "SET_ACTIVITY",
      args = {
        pid = 0,
        activity = activity,
      },
      nonce = string.format("%d-%d", globals.tickcount() or 0, math.floor((globals.realtime() or 0) * 1000) % 100000),
    }
    local encoded = nil
    pcall(function() encoded = json.stringify(payload) end)
    if encoded then
      local written = rpc_write(OPCODE_FRAME, encoded)
      if written then
        rpc.last_activity = activity
        return true
      end
    end
    return false
  end

  local function rpc_clear()
    if not rpc.ready then return end
    local payload = {
      cmd = "SET_ACTIVITY",
      args = { pid = 0, activity = json.null },
      nonce = string.format("clear-%d", globals.tickcount() or 0),
    }
    local encoded = nil
    pcall(function() encoded = json.stringify(payload) end)
    if not encoded then
      pcall(function()
        encoded = '{"cmd":"SET_ACTIVITY","args":{"pid":0,"activity":null},"nonce":"clear"}'
      end)
    end
    if encoded then rpc_write(OPCODE_FRAME, encoded) end
    rpc.last_activity = nil
    rpc.last_signature = nil
  end

  local function ensure_session_start()
    -- Prefer GameSense's Unix clock. Do not use globals.realtime/client.timestamp:
    -- those are monotonic milliseconds/seconds, not Unix epoch seconds required by Discord RPC.
    if type(rpc.session_start) == "number" and rpc.session_start > 1000000000 then
      return rpc.session_start
    end

    -- Keep the anchor on Class.misc as well as inside this RPC closure so incidental
    -- RPC reconnects or an off/on toggle cannot create a fresh elapsed-time counter.
    local shared_start = Class.misc and Class.misc._discord_rpc_session_start
    if type(shared_start) == "number" and shared_start > 1000000000 then
      rpc.session_start = math.floor(shared_start)
      return rpc.session_start
    end

    local start_time = nil
    if client and type(client.unix_time) == "function" then
      local ok, value = pcall(client.unix_time)
      if ok and type(value) == "number" and value > 1000000000 then
        start_time = value
      end
    end
    if not start_time and os and type(os.time) == "function" then
      local ok, value = pcall(os.time)
      if ok and type(value) == "number" and value > 1000000000 then
        start_time = value
      end
    end

    if start_time then
      rpc.session_start = math.floor(start_time)
      if Class.misc then
        Class.misc._discord_rpc_session_start = rpc.session_start
      end
    end
    return rpc.session_start
  end

  local function build_activity()
    -- The same Unix-second value is reused for every K/D/map update.
    ensure_session_start()

    local mapname = globals.mapname and globals.mapname() or nil
    local activity = {
      type = 0,
      name = "afterglow",
      details = "In main menu",
      assets = {
        -- Custom Rich Presence image asset uploaded as "a_painterly_textured_anime_style_illustration_in".
        large_image = "a_painterly_textured_anime_style_illustration_in",
        large_text = "afterglow",
      },
      instance = true,
    }
    if rpc.session_start ~= nil then
      activity.timestamps = { start = rpc.session_start }
    end

    if mapname and mapname ~= "" then
      -- Line 1 is activity.name; line 2 is the map; line 3 is K/D.
      activity.details = clean_mapname(mapname)

      local kills, deaths = 0, 0
      local lp = entity.get_local_player()
      local pr = entity.get_player_resource and entity.get_player_resource() or nil
      if lp and pr then
        kills = tonumber(entity.get_prop(pr, "m_iKills", lp)) or 0
        deaths = tonumber(entity.get_prop(pr, "m_iDeaths", lp)) or 0
      end
      local ratio
      if deaths <= 0 then
        ratio = kills > 0 and string.format("%.2f", kills) or "0.00"
      else
        ratio = string.format("%.2f", kills / deaths)
      end
      activity.state = string.format("K/D %d/%d (%s)", kills, deaths, ratio)
    end
    return activity
  end

  Class.misc.discord_rpc = {
    update = function(self)
      local enabled = false
      pcall(function()
        enabled = Class.ui.menu.misc_tab.discord_rpc:get() and true or false
      end)
      if not enabled then
        if rpc.ready and rpc.last_activity ~= nil then
          rpc_clear()
        end
        return
      end
      if not named_pipes_ok then return end
      if not rpc.open then
        rpc_connect()
      end
      rpc_read()
      if not rpc.ready then
        rpc_connect()
        rpc_read()
        return
      end
      local now = globals.realtime() or 0
      if now - (rpc.last_update or 0) < 1 then return end
      rpc.last_update = now
      local activity = build_activity()
      local signature = tostring(activity.name or "") .. "|" .. tostring(activity.details or "") .. "|" .. tostring(activity.state or "")
      -- SET_ACTIVITY is sent only for the first publish or when K/D/map actually changes.
      -- Every sent activity carries the exact same timestamps.start anchor.
      if signature ~= rpc.last_signature then
        if rpc_set_activity(activity) then
          rpc.last_signature = signature
        end
      end
    end,
    shutdown = function(self)
      pcall(rpc_clear)
      pcall(function()
        if rpc.pipe and rpc.pipe.close then rpc.pipe:close() end
      end)
      rpc.pipe, rpc.open, rpc.ready, rpc.last_activity = nil, false, false, nil
    end,
  }
end

  Class.misc.warmup_setup = {
   run = function(self)
     local cmds = {
      "sv_cheats 1",
      "sv_airaccelerate 100",
      "bot_stop 1",
      "mp_maxmoney 999999",
      "mp_startmoney 999999",
      "mp_afterroundmoney 999999",
      "mp_buytime 9999",
      "mp_buy_anywhere 1",
      "mp_freezetime 0",
      "mp_roundtime 60",
      "mp_roundtime_defuse 60",
      "mp_roundtime_hostage 60",
      "mp_ignore_round_win_conditions 1",
      "mp_respawn_on_death_ct 1",
      "mp_respawn_on_death_t 1",
      "sv_infinite_ammo 1",
      "mp_limitteams 0",
      "mp_autoteambalance 0",
      "mp_timelimit 0",
      "mp_respawnwavetime_ct 0",
      "mp_respawnwavetime_t 0",
      "mp_death_drop_gun 0",
      "ammo_grenade_limit_total 5",
      "sv_staminamax 0",
      "sv_staminajumpcost 0",
      "sv_staminalandcost 0",
      "sv_showimpacts 1",
      "mp_warmup_end",
     }
    for index = 1, #cmds do
      pcall(client.exec, cmds[index])
    end
end,
}
function Class.ui.print_event_logger_guide()
  local red, purple, white = "FF4B5C", "9B5CFF", "E1E1E1"
  local lines = {
   {{color=red,text="[ afterglow ]"}, {color=purple,text=" EVENT LOGGER GUIDE"}},
   {{color=red,text="p=TEXT"}, {color=white,text="  - custom prefix"}},
   {{color=purple,text="nh"}, {color=white,text="      - disable prefix color"}},
   {{color=red,text="b=[]"}, {color=white,text="    - custom brackets"}},
   {{color=purple,text="nb"}, {color=white,text="      - remove brackets"}},
   {{color=red,text="np"}, {color=white,text="      - disable prefix"}},
   {{color=white,text="Plain text can also be used as a prefix."}},
   {{color=white,text="Commands are separated by spaces. "}, {color=purple,text="b=XY"}, {color=white,text=" uses X as left and Y as right bracket."}}
  }
  for index = 1, #lines do
    Class.util:chat_print_colored(lines[index])
  end
end
Class.misc.event_logger = {
 shots = {},
 bullet_impacts = {},
 hitgroups = {"generic", "head", "chest", "stomach", "left arm", "right arm", "left leg", "right leg", "neck", "?", "gear"},
 _get_color = function(self, field, fallback)
   fallback = fallback or {240, 240, 240}
   local element = nil
   pcall(function()
     element = Class.ui.menu.misc_tab.event_logger.color[field]
   end)
   if not element then return {fallback[1], fallback[2], fallback[3]} end
   local ok, r, g, b = pcall(element.get, element)
   if not ok then return {fallback[1], fallback[2], fallback[3]} end
   if type(r) == "table" then
     g, b = r[2] or r.g, r[3] or r.b
     r = r[1] or r.r
   end
   r, g, b = tonumber(r), tonumber(g), tonumber(b)
   if not r or not g or not b then return {fallback[1], fallback[2], fallback[3]} end
   return {
     math.max(0, math.min(255, math.floor(r + 0.5))),
     math.max(0, math.min(255, math.floor(g + 0.5))),
     math.max(0, math.min(255, math.floor(b + 0.5)))
   }
 end,
 _log_prefix = function(self, accent, white)
   local logger = Class.ui.menu.misc_tab.event_logger
   local raw = ""
   pcall(function() raw = logger.prefix:get() or "" end)

   return Class.util:format_log_prefix(raw, accent or white, white, accent or white)
 end,
 _emit = function(self, accent, white, parts)
   local message = self:_log_prefix(accent, white)
   for index = 1, #parts do
     message[#message + 1] = parts[index]
   end
   if #message > 0 then
     local last = message[#message]
     if last.text and type(last.text) == "string" and last.text:sub(-1) ~= string.char(10) then
       last.text = last.text .. string.char(10)
     end
   end
   Class.util.output_message(message)
 end,
 _reason = function(self, shot, e)
   local raw = e and e.reason or nil
   if shot and shot.handle_time and (globals.realtime() - shot.handle_time) >= 0.5 then
     return "event timeout"
   end

   local local_player = entity.get_local_player()
   local fired_hits = shot and tonumber(shot.total_hits)
   local current_hits = local_player and tonumber(entity.get_prop(local_player, "m_totalHitsOnServer"))
   if fired_hits ~= nil and current_hits ~= nil and current_hits > fired_hits then
     return "damage rejection"
   end

   if raw == "prediction error" then
     return "prediction error"
   end
   if raw == "unregistered shot" then
     return "unregistered shot"
   end
   if raw == "spread" then
     return "spread"
   end
   if raw == "death" then
     return "death"
   end
   if raw == "occlusion" then
     return "occlusion"
   end
   if raw == "?" or raw == nil or raw == "" then
     return "correction"
   end
   return tostring(raw)
 end,
 _get_shot = function(self, e)
   if not e or e.id == nil then return nil, nil end
   return self.shots[e.id], e.id
 end,
 _prune = function(self)
   local now = globals.realtime() or 0
   for id, shot in pairs(self.shots) do
     if not shot.handle_time or now - shot.handle_time > 2.0 then
       self.shots[id] = nil
     end
   end
   for tick, impact in pairs(self.bullet_impacts) do
     if not impact.time or now - impact.time > 1.0 then
       self.bullet_impacts[tick] = nil
     end
   end
 end,
 on_net_update_start = function(self)
   self:_prune()
 end,
 on_aim_fire = function(self, e)
   if not e or e.id == nil then return end
   local tick = globals.tickcount()
   self.shots[e.id] = {
     id = e.id,
     target = e.target,
     original = e,
     damage = tonumber(e.damage) or 0,
     hitchance = tonumber(e.hit_chance) or 0,
     hitbox = e.hitgroup,
     history = tick - (e.tick or tick),
     fire_tick = tick,
     total_hits = tonumber(entity.get_prop(entity.get_local_player(), "m_totalHitsOnServer")) or 0,
     handle_time = globals.realtime(),
   }
   self:_prune()
 end,
 on_bullet_impact = function(self, e)
   if not e then return end
   local me = entity.get_local_player()
   if not me then return end
   local user = client.userid_to_entindex(e.userid)
   if user ~= me then return end
   local tick = globals.tickcount()
   self.bullet_impacts[tick] = {
     time = globals.realtime(),
     shot = vector(e.x, e.y, e.z),
   }
 end,
 on_aim_hit = function(self, e)
   local logger = Class.ui.menu.misc_tab.event_logger
   if not logger.enabled:get() or not logger.triggers.event_triggers:get("Aimbot") then return end
   local shot, id = self:_get_shot(e)
   if not shot then
     shot = {
       id = e and e.id,
       target = e and e.target,
       damage = tonumber(e and e.damage) or 0,
       hitchance = tonumber(e and e.hit_chance) or 0,
       hitbox = e and e.hitgroup,
       history = 0,
       total_hits = tonumber(entity.get_prop(entity.get_local_player(), "m_totalHitsOnServer")),
     }
   end
   local accent = self:_get_color("hit_purchase_color", {255, 255, 255})
   local white = {240, 240, 240}
   local target = e and e.target or shot.target
   local target_name = target and entity.get_player_name(target) or "?"
   local hitbox = self.hitgroups[(tonumber(e and e.hitgroup) or 0) + 1] or "?"
   local aimed_hitbox = self.hitgroups[(tonumber(shot.hitbox) or 0) + 1] or "?"
   local damage = tonumber(e and e.damage) or shot.damage or 0
   local hitchance = math.floor((shot.hitchance or e.hit_chance or 0) + 0.5)
   local bt = tonumber(shot.history) or 0
   local expected = tonumber(shot.damage) or 0
   local delay_ticks = 0
   pcall(function()
     local fire_tick = tonumber(shot.fire_tick)
     local current_tick = tonumber(globals.tickcount())
     if fire_tick and current_tick then
       delay_ticks = math.max(current_tick - fire_tick - 1, -2)
     end
   end)
   local delay = 0
   pcall(function()
     local tickinterval = tonumber(globals.tickinterval()) or 0
     delay = math.floor(delay_ticks * tickinterval * 1000 + (delay_ticks >= 0 and 0.5 or -0.5))
   end)
   local target_health = tonumber(e and e.health)
   if target_health == nil and target then
     target_health = tonumber(entity.get_prop(target, "m_iHealth"))
   end
   local killed = target_health ~= nil and target_health <= 0
   local hitbox_mismatch = aimed_hitbox ~= "?" and hitbox ~= aimed_hitbox
   local damage_mismatch = expected > 0 and expected ~= damage
   local parts
   if killed then
     parts = {
       { text = "Killed ", color = white },
       { text = target_name, color = accent },
       { text = " in ", color = white },
       { text = hitbox, color = accent },
     }
   else
     parts = {
       { text = "Hit ", color = white },
       { text = target_name, color = accent },
       { text = "'s ", color = white },
       { text = hitbox, color = accent },
     }
   end
   if hitbox_mismatch then
     parts[#parts + 1] = { text = " (expected hitbox: ", color = white }
     parts[#parts + 1] = { text = aimed_hitbox, color = accent }
     parts[#parts + 1] = { text = ")", color = white }
   end
   parts[#parts + 1] = { text = " for ", color = white }
   parts[#parts + 1] = { text = tostring(math.floor(damage + 0.5)), color = accent }
   if damage_mismatch then
     parts[#parts + 1] = { text = " (missmatched for: ", color = white }
     parts[#parts + 1] = { text = tostring(math.floor(expected + 0.5)), color = accent }
     parts[#parts + 1] = { text = ")", color = white }
   end
   parts[#parts + 1] = { text = " damage (", color = white }
   parts[#parts + 1] = { text = target_health ~= nil and tostring(math.max(0, math.floor(target_health + 0.5))) or "?", color = accent }
   parts[#parts + 1] = { text = " hp left) (bt: ", color = white }
   parts[#parts + 1] = { text = tostring(bt) .. "t", color = accent }
   parts[#parts + 1] = { text = " · hc: ", color = white }
   parts[#parts + 1] = { text = tostring(hitchance) .. "%", color = accent }
   parts[#parts + 1] = { text = ") (delay=", color = white }
   parts[#parts + 1] = { text = tostring(delay) .. "ms", color = accent }
   parts[#parts + 1] = { text = ")", color = white }
   self:_emit(accent, white, parts)

   if Class.misc.notifications_ui and Class.misc.notifications_ui:should_show("Hit") then
     local notif
     if killed then
       notif = string.format("/rKilled /v%s/r in /v%s/r for /v%d/r damage", target_name, hitbox, damage)
     else
       notif = string.format("/rHit /v%s/r's /v%s/r for /v%d/r damage", target_name, hitbox, damage)
     end
     Class.render.notifications:push(notif, "hit")
   end
   if id ~= nil then self.shots[id] = nil end
 end,
 on_aim_miss = function(self, e)
   local logger = Class.ui.menu.misc_tab.event_logger
   if not logger.enabled:get() or not logger.triggers.event_triggers:get("Aimbot") then return end
   local shot, id = self:_get_shot(e)
   if not shot then
     shot = {
       id = e and e.id,
       target = e and e.target,
       damage = 0,
       hitchance = tonumber(e and e.hit_chance) or 0,
       hitbox = e and e.hitgroup,
       history = 0,
     }
   end
   local accent = self:_get_color("miss_connection_color", {225, 80, 80})
   local white = {240, 240, 240}
   local target = e and e.target or shot.target
   local target_name = target and entity.get_player_name(target) or "?"
   local hitbox = self.hitgroups[(tonumber(e and e.hitgroup) or 0) + 1] or "?"
   local aimed_hitbox = self.hitgroups[(tonumber(shot.hitbox) or 0) + 1] or "?"
   local reason = self:_reason(shot, e)
   local backtrack = tonumber(shot.history) or 0
   local hitchance = math.floor((shot.hitchance or e.hit_chance or 0) + 0.5)
   local pred = tonumber(shot.damage) or 0
   local delay_ticks = 0
   pcall(function()
     local fire_tick = tonumber(shot.fire_tick)
     local current_tick = tonumber(globals.tickcount())
     if fire_tick and current_tick then
       delay_ticks = math.max(current_tick - fire_tick - 1, -2)
     end
   end)
   local delay = 0
   pcall(function()
     local tickinterval = tonumber(globals.tickinterval()) or 0
     delay = math.floor(delay_ticks * tickinterval * 1000 + (delay_ticks >= 0 and 0.5 or -0.5))
   end)
   local parts = {
     { text = "Missed in ", color = white },
     { text = target_name, color = accent },
     { text = "'s ", color = white },
     { text = hitbox, color = accent },
     { text = " due to ", color = white },
     { text = reason, color = accent },
   }
   if pred > 0 then
     parts[#parts + 1] = { text = " (dmg: ", color = white }
     parts[#parts + 1] = { text = tostring(math.floor(pred + 0.5)), color = accent }
     parts[#parts + 1] = { text = " · hitbox: ", color = white }
     parts[#parts + 1] = { text = aimed_hitbox, color = accent }
     parts[#parts + 1] = { text = ") (bt: ", color = white }
   else
     parts[#parts + 1] = { text = " (bt: ", color = white }
   end
   parts[#parts + 1] = { text = tostring(backtrack) .. "t", color = accent }
   parts[#parts + 1] = { text = " · hc: ", color = white }
   parts[#parts + 1] = { text = tostring(hitchance) .. "%", color = accent }
   parts[#parts + 1] = { text = ") (delay=", color = white }
   parts[#parts + 1] = { text = tostring(delay) .. "ms", color = accent }
   parts[#parts + 1] = { text = ")", color = white }
   self:_emit(accent, white, parts)

   if Class.misc.notifications_ui and Class.misc.notifications_ui:should_show("Miss") then
     Class.render.notifications:push(
       string.format("/rMissed in /v%s/r's /v%s/r due to /v%s/r", target_name, hitbox, reason),
       "miss"
     )
   end
   if id ~= nil then self.shots[id] = nil end
 end,
 on_player_hurt = function(self, e)
   local logger = Class.ui.menu.misc_tab.event_logger
   if not logger.enabled:get() or not logger.triggers.event_triggers:get("Aimbot") then return end
   local local_player = entity.get_local_player()
   if not local_player then return end
   local attacker = client.userid_to_entindex(e.attacker)
   local victim = client.userid_to_entindex(e.userid)
   if attacker ~= local_player or victim == local_player then return end
   local weapon = tostring(e.weapon or ""):lower():gsub("^weapon_", "")
   local verb
   if weapon == "inferno" or weapon == "molotov" or weapon == "incgrenade" then
     verb = "Burned"
   elseif weapon == "hegrenade" then
     verb = "Naded"
   elseif weapon:find("knife", 1, true) or weapon == "bayonet" then
     verb = "Knifed"
   end
   if not verb then return end
   local accent = self:_get_color("hit_purchase_color", {255, 255, 255})
   local white = {240, 240, 240}
   local target_name = entity.get_player_name(victim) or "?"
   local damage = math.floor(tonumber(e.dmg_health) or 0)
   local remaining = math.max(0, math.floor(tonumber(e.health) or 0))
   self:_emit(accent, white, {
     { text = verb .. " ", color = white },
     { text = target_name, color = accent },
     { text = " for ", color = white },
     { text = tostring(damage), color = accent },
     { text = " damage (", color = white },
     { text = tostring(remaining), color = accent },
     { text = " health remaining)", color = white },
   })
 end,
 on_item_purchase = function(self, e)
   local logger = Class.ui.menu.misc_tab.event_logger
   if not logger.enabled:get() or not logger.triggers.event_triggers:get("Purchase") then return end
   local purchaser = client.userid_to_entindex(e.userid)
   if not purchaser or purchaser == 0 or purchaser == entity.get_local_player() then return end
   local target_name = entity.get_player_name(purchaser)
   if not target_name then return end
   local accent = self:_get_color("hit_purchase_color", {255, 255, 255})
   local white = {240, 240, 240}
   local weapon_name = e.weapon and e.weapon:gsub("^%l", string.lower) or "unknown"
   self:_emit(accent, white, {
     { text = target_name, color = accent },
     { text = " Bought ", color = white },
     { text = weapon_name, color = accent },
   })
 end,
}
end
local function viewmodel_feature_enabled(name)
  local menu = Class.ui and Class.ui.menu
  local visuals = menu and menu.visuals_tab
  local other = visuals and visuals.other
  local viewmodel_ui = other and other.viewmodel_changer
  if not viewmodel_ui or not viewmodel_ui.features then return false end
  local ok, enabled = pcall(viewmodel_ui.features.get, viewmodel_ui.features, name)
  return ok and enabled == true
end
do
  local MATERIAL_VAR_NO_DRAW = 2
  local hidden_sleeves = {}
  local last_enabled = false
  local active_map = nil
  local next_attempt = 0

  local function current_map_name()
    local ok, name = pcall(function() return globals.mapname() end)
    return ok and tostring(name or "") or ""
  end

  local function restore_sleeves()
    for index = 1, #hidden_sleeves do
      local material = hidden_sleeves[index]
      pcall(function()
        material:set_material_var_flag(MATERIAL_VAR_NO_DRAW, false)
      end)
    end
    hidden_sleeves = {}
  end

  local function set_remove_sleeves(value, current_time)
    if not value then
      if last_enabled then
        restore_sleeves()
      end
      last_enabled = false
      active_map = nil
      next_attempt = 0
      return
    end

    local map_name = current_map_name()
    if last_enabled and map_name == active_map then
      return
    end

    -- Rebuild only on first activation or map change. Do not toggle material
    -- flags on a timer: doing so briefly shows the sleeves between refreshes.
    if last_enabled then
      restore_sleeves()
      last_enabled = false
    end

    if current_time < next_attempt then
      return
    end
    next_attempt = current_time + 1.0

    local success, materials = pcall(materialsystem.find_materials, "sleeve", true)
    if not success or type(materials) ~= "table" then
      return
    end

    for _, material in pairs(materials) do
      local flag_ok, no_draw = pcall(function()
        return material:get_material_var_flag(MATERIAL_VAR_NO_DRAW)
      end)
      if flag_ok and not no_draw then
        local set_ok = pcall(function()
          material:set_material_var_flag(MATERIAL_VAR_NO_DRAW, true)
        end)
        if set_ok then
          hidden_sleeves[#hidden_sleeves + 1] = material
        end
      end
    end

    active_map = map_name
    last_enabled = true
  end

  Class.util.remove_sleeves = {
    update = function(self)
      pcall(function()
        local current_time = globals.realtime() or 0
        local enabled = false
        local menu = Class.ui and Class.ui.menu
        local viewmodel_changer = menu and menu.visuals_tab and menu.visuals_tab.other and menu.visuals_tab.other.viewmodel_changer
        if viewmodel_changer and viewmodel_changer.enabled then
          local en = false
          pcall(function() en = viewmodel_changer.enabled:get() and true or false end)
          if en and viewmodel_feature_enabled("Remove Sleeves") then
            enabled = true
          end
        end
        set_remove_sleeves(enabled, current_time)
      end)
    end,
    restore = function(self)
      pcall(restore_sleeves)
      last_enabled = false
      active_map = nil
      next_attempt = 0
    end,
  }
end
Class.network = {
 channel = nil,
 last_ping = nil,
 high_ping = false,
 high_loss = false,
 spike_time = 0,
 initialized = false,
 setup = function(self)
   if self.initialized then return end
   self.initialized = true
   pcall(function()
     local class_ptr = ffi.typeof("void***")
     local engine_client = ffi.cast(class_ptr, client.create_interface("engine.dll", "VEngineClient014"))
     local get_channel = ffi.cast("void*(__thiscall*)(void*)", engine_client[0][78])
     self.channel = {
       engine_client = engine_client,
       get_channel = get_channel,
       class_ptr = class_ptr,
       netc_bool = ffi.typeof("bool(__thiscall*)(void*)"),
       netc_float = ffi.typeof("float(__thiscall*)(void*, int)"),
     }
   end)
 end,
 read = function(self)
   self:setup()
   if not self.channel then return nil end
   local data
   pcall(function()
     local c = self.channel
     local net_channel = c.get_channel(c.engine_client)
     if net_channel == nil then return end
     local info = ffi.cast(c.class_ptr, net_channel)
     local loopback = ffi.cast(c.netc_bool, info[0][6])(info)
     local channel_ping = ffi.cast(c.netc_float, info[0][10])(info, 1) * 1000
     local loss = ffi.cast(c.netc_float, info[0][11])(info, 1) * 100
     local ping = channel_ping
     pcall(function()
       local resource = entity.get_player_resource()
       local local_player = entity.get_local_player()
       local score_ping = resource and local_player and entity.get_prop(resource, "m_iPing", local_player)
       if score_ping and tonumber(score_ping) and tonumber(score_ping) > 0 then
         ping = tonumber(score_ping)
       end
     end)
     data = {
       loopback = loopback,
       ping = ping,
       loss = loss,
     }
   end)
   return data
 end,
 notify = function(self, title, detail)
   local logger = Class.ui.menu.misc_tab.event_logger
   if not logger or not logger.enabled:get() then return end
   if not logger.triggers.event_triggers:get("Connection problems") then return end
   local accent = {255, 0, 0}
   Class.misc.event_logger:_emit(accent, {240, 240, 240}, {
     { text = title .. " ", color = {240, 240, 240} },
     { text = detail, color = accent },
   })
   if logger.triggers.event_triggers:get("On Screen") then
     Class.render.notifications:push(
       "/r" .. title .. " /v" .. detail .. "/r",
       "connection"
     )
   end
 end,
 update = function(self)
   local logger = Class.ui.menu.misc_tab.event_logger
   if not logger or not logger.enabled:get() or not logger.triggers.event_triggers:get("Connection problems") then
     self.high_ping = false
     self.high_loss = false
     self.last_ping = nil
     return
   end
   local data = self:read()
   if not data or data.loopback then return end
   local now = globals.realtime() or 0
   local ping = math.max(0, tonumber(data.ping) or 0)
   local loss = math.max(0, tonumber(data.loss) or 0)
   if ping <= 0 then
     local latency = nil
     pcall(function() latency = client.latency() end)
     if latency then ping = math.max(0, latency * 1000) end
   end
   if ping <= 0 then
     self.last_ping = nil
     return
   end
   local ping_spike = self.last_ping ~= nil and math.abs(ping - self.last_ping) >= 35 and now >= (self.spike_time or 0)
   if ping >= 120 and not self.high_ping then
     self:notify("High ping", string.format("%d ms", math.floor(ping + 0.5)))
     self.high_ping = true
   elseif ping < 100 then
     self.high_ping = false
   end
   if loss >= 5 and not self.high_loss then
     self:notify("Packet loss", string.format("%.1f%%", loss))
     self.high_loss = true
   elseif loss < 3 then
     self.high_loss = false
   end
   if ping_spike then
     local previous = self.last_ping
     local change = ping - previous
     self:notify("Ping spike", string.format("%d → %d ms (%+d ms)", math.floor(previous + 0.5), math.floor(ping + 0.5), math.floor(change + (change >= 0 and 0.5 or -0.5))))
     self.spike_time = now + 2
   end
   self.last_ping = ping
 end,
}
local function apply_patch_set(patches)
  local memory = Class.gamesense._mem
  for _, patch in ipairs(patches) do
    local current = memory.read(patch.address, #patch.original)
    if not current then return false end
    if not memory.match(current, patch.original) and not memory.match(current, patch.patched) then
      return false
    end
  end
  for _, patch in ipairs(patches) do
    local current = memory.read(patch.address, #patch.original)
    if memory.match(current, patch.original) and not memory.write(patch.address, patch.patched) then
      return false
    end
  end
  return true
end
local function restore_patch_set(patches)
  local memory = Class.gamesense._mem
  for _, patch in ipairs(patches) do
    local current = memory.read(patch.address, #patch.patched)
    if memory.match(current, patch.patched) and not memory.write(patch.address, patch.original) then
      return false
    end
  end
  return true
end
pcall(ffi.cdef, [[int __stdcall VirtualProtect(void*, uintptr_t, unsigned long, unsigned long*);]])
local function resolve_signature_address(pattern)
 local ok, match = pcall(client.find_signature, "client.dll", pattern)
 if not ok or not match then return nil end
 local number_ok, address = pcall(tonumber, match)
 if not number_ok or not address or address == 0 then
  local cast_ok, cast_address = pcall(function() return tonumber(ffi.cast("uintptr_t", match)) end)
  if not cast_ok then return nil end
  address = cast_address
 end
 if not address or address == 0 then return nil end
 return address
end

local function make_native_literal_fix(name, pattern, offset, original, patched)
 return {
  _active = false,
  _site = nil,
  _original = original,
  _patched = patched,
  _last_attempt = -10,
  apply = function(self)
   if self._active then return true end
   local base = resolve_signature_address(pattern)
   if not base then return false end
   local address = base + offset
   local mem = Class.gamesense._mem
   local current = mem.read(address, #self._original)
   if mem.match(current, self._patched) then
    self._site = {address = address, changed = false}
    self._active = true
    return true
   end
   if not mem.match(current, self._original) then return false end
   if not mem.write(address, self._patched) then return false end
   if not mem.match(mem.read(address, #self._patched), self._patched) then
    local verify = mem.read(address, #self._patched)
    if mem.match(verify, self._patched) then mem.write(address, self._original) end
    return false
   end
   self._site = {address = address, changed = true}
   self._active = true
   return true
  end,
  restore = function(self)
   local site = self._site
   if not site then self._active = false return true end
   local mem = Class.gamesense._mem
   if site.changed then
    local current = mem.read(site.address, #self._patched)
    if mem.match(current, self._patched) then
     if not mem.write(site.address, self._original) then return false end
    elseif not mem.match(current, self._original) then
     return false
    end
   end
   self._site = nil
   self._active = false
   return true
  end,
  handle = function(self, control)
   local enabled = false
   pcall(function() enabled = control.enabled:get() and true or false end)
   if not enabled or globals.mapname() == nil then
    self:restore()
    return
   end
   if self._active then return end
   local now = globals.realtime() or 0
   if now - self._last_attempt < 1 then return end
   self._last_attempt = now
   self:apply()
  end,
 }
end


-- Extended Yaw (GS): Persistence-style tune + LBY breaker, roll-free. Native Yaw 180+/-90
-- manuals, Body Static +/-60 (back/left +, right -), pitch down 89, roll 0 on EVERY command
-- ([BypassMasive]/rollaa.sp check angles[2] on sent AND choked cmds, so any roll is detected).
-- fake = real + ext (additive fixed sign); inverter flips body side. Optional FFI defensive
-- (cmd.force_defensive + break_lc choke) hides the shot during exploit so the real angle is
-- not onshot — the GS-native equivalent of NL's trusted-wire + hidden-shot serialize logic.
do
  local BODY_MAX = 60

  local refs = {
    enabled = nil,
    pitch = nil,
    pitch_value = nil,
    yaw_base = nil,
    yaw = nil,
    yaw_value = nil,
    yaw_jitter = nil,
    yaw_jitter_value = nil,
    body = nil,
    body_value = nil,
    roll = nil,
    edge = nil,
  }
  pcall(function() refs.enabled = ui.reference("AA", "Anti-aimbot angles", "Enabled") end)
  pcall(function()
    local a, b = ui.reference("AA", "Anti-aimbot angles", "Pitch")
    refs.pitch, refs.pitch_value = a, b
  end)
  pcall(function() refs.yaw_base = ui.reference("AA", "Anti-aimbot angles", "Yaw base") end)
  pcall(function()
    local a, b = ui.reference("AA", "Anti-aimbot angles", "Yaw")
    refs.yaw, refs.yaw_value = a, b
  end)
  pcall(function()
    local a, b = ui.reference("AA", "Anti-aimbot angles", "Body yaw")
    refs.body, refs.body_value = a, b
  end)
  pcall(function() refs.roll = ui.reference("AA", "Anti-aimbot angles", "Roll") end)
  pcall(function() refs.edge = ui.reference("AA", "Anti-aimbot angles", "Edge yaw") end)
  pcall(function()
    local a, b = ui.reference("AA", "Anti-aimbot angles", "Yaw jitter")
    refs.yaw_jitter, refs.yaw_jitter_value = a, b
  end)

  local function is_ladder(ent)
    return (entity.get_prop(ent, "m_MoveType") or 0) == 9
  end

  local function speed_of(ent)
    local vx = entity.get_prop(ent, "m_vecVelocity[0]") or 0
    local vy = entity.get_prop(ent, "m_vecVelocity[1]") or 0
    return math.sqrt(vx * vx + vy * vy)
  end

  local function is_grenade_weapon(local_player)
    local weapon = entity.get_player_weapon(local_player)
    if not weapon then return false end
    local cls = entity.get_classname(weapon) or ""
    if cls:find("Grenade", 1, true) then return true end
    local idx = entity.get_prop(weapon, "m_iItemDefinitionIndex")
    if type(idx) == "number" then
      idx = bit.band(idx, 0xFFFF)
      if idx >= 43 and idx <= 48 then return true end
    end
    return false
  end

  local function micro_move(cmd, local_player)
    if cmd.chokedcommands == 0 then return end
    if speed_of(local_player) > 3.1 then return end
    if cmd.in_attack == 1 or cmd.in_use == 1 then return end
    local qp = Class.util.reference and Class.util.reference.rage_peek_assist
    if qp and qp[1] and qp[2] then
      local ok1, e1 = pcall(ui.get, qp[1])
      local ok2, e2 = pcall(ui.get, qp[2])
      if ok1 and ok2 and e1 and e2 then return end
    end
    -- LBY break: a tiny forward nudge on choked commands keeps the lower-body yaw
    -- updating every fake tick so it never settles into a resolvable angle. This is
    -- the proven micro-move from working LBY breakers and works even if roll is patched.
    cmd.forwardmove = 0.1
    cmd.in_forward = 1
    cmd.sidemove = 0
    cmd.in_moveleft = 0
    cmd.in_moveright = 0
  end

  -- Fake pitch resolver, subset of the observed Persistence defensive.5 pitch modes.
  -- Down/Up/Custom/Random/Disabled; Swap/Switch/Sway/Spin/Meta/3-way intentionally omitted.
  local function resolve_pitch(menu)
    local mode = "Down"
    pcall(function() mode = menu.pitch_mode:get() or "Down" end)
    if mode == "Disabled" then return nil end
    if mode == "Up" then return -89 end
    if mode == "Custom" then
      local v = 89
      pcall(function() v = menu.pitch_value:get() or 89 end)
      return v
    end
    if mode == "Random" then return math.random(-89, 89) end
    return 89
  end

  local function apply_static_aa(yaw_offset, body_side, pitch_val, yaw_base)
    -- Static stack: fixed yaw, static body on a steady side. Resolver resistance comes
    -- from the roll unlock + LBY micro-move + cmd.yaw extension below, not from jitter.
    if refs.enabled then pcall(ui.set, refs.enabled, true) end
    if refs.pitch then
      if pitch_val == nil then
        pcall(ui.set, refs.pitch, "Default")
      else
        pcall(ui.set, refs.pitch, "Custom")
        if refs.pitch_value then pcall(ui.set, refs.pitch_value, pitch_val) end
      end
    end
    if refs.yaw_base then pcall(ui.set, refs.yaw_base, yaw_base or "Local view") end
    if refs.edge then pcall(ui.set, refs.edge, false) end
    if refs.yaw then
      -- "180" mode + offset: 0 = backward base, ±90 = side manuals.
      pcall(ui.set, refs.yaw, "180")
      if refs.yaw_value then pcall(ui.set, refs.yaw_value, yaw_offset) end
    end
    if refs.yaw_jitter then
      pcall(ui.set, refs.yaw_jitter, "Off")
      if refs.yaw_jitter_value then pcall(ui.set, refs.yaw_jitter_value, 0) end
    end
    if refs.body then
      pcall(ui.set, refs.body, "Static")
      if refs.body_value then pcall(ui.set, refs.body_value, body_side) end
    end
    if refs.roll then pcall(ui.set, refs.roll, 0) end
  end

  -- Manual selection: a single direction with proper toggle/hold semantics (mirrors the
  -- builder). Naive :get() booleans let a toggled-left stay on and block right/backward.
  local man_sel = 0
  local man_down = { false, false }
  local man_key = { nil, nil }
  local function read_manual(menu)
    local elems = { menu.manual_left, menu.manual_right }
    local sel = man_sel
    for i = 1, 2 do
      local el = elems[i]
      local active, mode, key = false, nil, nil
      if el and el.ref then
        local ok, a, m, k = pcall(ui.get, el.ref)
        if ok then active, mode, key = (a == true), m, k end
      end
      if type(key) ~= "number" then key = tonumber(key) end
      local mnorm = tostring(mode or "on hotkey"):lower():gsub("[%s_%-]+", "")
      local down = false
      if key ~= nil then
        if man_key[i] ~= key then man_key[i] = key; man_down[i] = false end
        local ok, pd = pcall(client.key_state, key)
        down = ok and pd == true or false
      end
      if mnorm == "toggle" then
        if down and not man_down[i] then sel = (sel == i) and 0 or i end
      elseif mnorm == "onhotkey" then
        if down then sel = i elseif sel == i then sel = 0 end
      elseif mnorm == "offhotkey" then
        if key ~= nil and not down then sel = i elseif sel == i then sel = 0 end
      elseif mnorm == "alwayson" then
        sel = i
      else
        if active then sel = i elseif sel == i then sel = 0 end
      end
      man_down[i] = down
    end
    man_sel = sel
    return sel
  end

  -- Master activation bind for the whole extended-yaw stack. The checkbox stays the
  -- feature enable / depend anchor (a pui hotkey cannot anchor depends), this hotkey
  -- gates runtime activation with proper toggle/hold semantics. Unbound => stays on,
  -- so existing configs keep working until a key is assigned.
  local bind_sel, bind_down, bind_key = false, false, nil
  local function read_bind(menu)
    local el = menu.bind
    if not el or not el.ref then return true end
    local ok, a, m, k = pcall(ui.get, el.ref)
    if not ok then return true end
    local key = tonumber(k)
    if key == nil or key == 0 then return true end
    if bind_key ~= key then bind_key = key; bind_down = false end
    local mode = tostring(m or "on hotkey"):lower():gsub("[%s_%-]+", "")
    local ok2, pd = pcall(client.key_state, key)
    local down = ok2 and pd == true or false
    if mode == "toggle" then
      if down and not bind_down then bind_sel = not bind_sel end
      bind_down = down
      return bind_sel
    elseif mode == "onhotkey" then
      bind_down = down
      return down
    elseif mode == "offhotkey" then
      bind_down = down
      return not down
    elseif mode == "alwayson" then
      return true
    end
    return a == true
  end

  -- Flick exploit (ported from aesthetic_skeet.lua flick_exploit:update). During an
  -- active exploit (double tap / on-shot AA) it owns ONLY pitch + periodic force_defensive
  -- (command_number % 7) and roll 0. Yaw / body / freestanding stay with the builder AA —
  -- flick never turns the fake angle left/right.
  local flick_pitch_inverted = false
  local flick_generated_pitch = 0

  local function flick_exploit_active()
    -- Gate on ACTUAL tickbase shifting (the aesthetic's exploit.get().shift), not merely
    -- "DT enabled" — otherwise flick fires every tick DT is toggled on and the indicator
    -- never clears. Use the live antiaim_funcs state.
    local shifting = false
    pcall(function()
      if antiaim_funcs and type(antiaim_funcs.get_tickbase_shifting) == "function" then
        local s = tonumber(antiaim_funcs.get_tickbase_shifting())
        if s and s ~= 0 then shifting = true end
      end
    end)
    if shifting then return true end
    -- Fallback for builds without the shifting API: DT / on-shot AA enabled+active.
    local active = false
    pcall(function()
      local dt = Class.util.reference.rage_double_tap
      if dt and dt[1] and dt[2] and ui.get(dt[1]) and ui.get(dt[2]) then active = true end
    end)
    if active then return true end
    pcall(function()
      local hs = Class.util.reference.aa_hideshots
      if hs and hs[1] and hs[2] and ui.get(hs[1]) and ui.get(hs[2]) then active = true end
    end)
    return active
  end

  local function flick_state(lp)
    local flags = entity.get_prop(lp, "m_fFlags") or 0
    local onground = bit.band(flags, 1) == 1
    local crouched = (entity.get_prop(lp, "m_flDuckAmount") or 0) > 0.5
    local vx = entity.get_prop(lp, "m_vecVelocity[0]") or 0
    local vy = entity.get_prop(lp, "m_vecVelocity[1]") or 0
    local moving = math.sqrt(vx * vx + vy * vy) > 3.1
    if not onground then
      if crouched then return "Air-Crouch" end
      return "Air"
    end
    if crouched then
      if moving then return "Move-Crouch" end
      return "Crouch"
    end
    if moving then
      local slow = false
      pcall(function()
        local sw = Class.util.reference.aa_slow_walk
        if sw and sw[1] then slow = ui.get(sw[1]) and true or false end
      end)
      if slow then return "Slow Walk" end
      return "Moving"
    end
    return "Standing"
  end

  local function flick_weapon_ok(lp)
    local weapon = entity.get_player_weapon(lp)
    if not weapon then return false end
    local idx = entity.get_prop(weapon, "m_iItemDefinitionIndex")
    if type(idx) == "number" then
      idx = bit.band(idx, 0xFFFF)
      if idx == 64 then return false end
      if idx >= 43 and idx <= 48 then return false end
      if idx >= 500 and idx < 600 then return false end
    end
    local cls = entity.get_classname(weapon) or ""
    if cls:find("Grenade", 1, true) or cls:find("Knife", 1, true) then return false end
    if cls == "CKnife" or cls == "CWeaponTaser" or cls == "CC4" then return false end
    return true
  end

  local function flick_pitch_value(menu, cmd)
    local mode = "Off"
    pcall(function() mode = menu.flick_pitch:get() or "Off" end)
    if mode == "Off" then return nil end
    local p1, p2 = 0, 0
    pcall(function() p1 = menu.flick_pitch_1:get() or 0 end)
    pcall(function() p2 = menu.flick_pitch_2:get() or 0 end)
    local lo, hi = math.min(p1, p2), math.max(p1, p2)
    if mode == "Static" then return p1 end
    if mode == "Sway" then
      local speed = 20
      pcall(function() speed = menu.flick_speed:get() or 20 end)
      local t = (globals.curtime() * speed * 0.1) % 1
      return p1 + (p2 - p1) * t
    end
    if mode == "Switch" then return flick_pitch_inverted and p2 or p1 end
    if mode == "Random" then return math.random(lo, hi) end
    if mode == "Static Random" then
      -- aesthetic regenerates when the exploit defensive buffer is full; GS-native proxy
      -- is a fresh random pitch on each sent (choke 0) tick.
      if cmd.chokedcommands == 0 then flick_generated_pitch = math.random(lo, hi) end
      return flick_generated_pitch
    end
    return nil
  end

  local function flick_run(cmd, menu, lp)
    if not menu.flick or not menu.flick:get() then return false end
    -- Builder manual direction has priority: flick must not twist the manual yaw.
    if (tonumber(Class.util.antiaim.manual_direction) or 0) ~= 0 then return false end
    if not flick_exploit_active() then return false end
    if not flick_weapon_ok(lp) then return false end
    local state = flick_state(lp)
    local selected = false
    pcall(function() selected = menu.flick_states:get(state) and true or false end)
    if not selected then return false end

    if cmd.chokedcommands == 0 then flick_pitch_inverted = not flick_pitch_inverted end

    -- Flick owns only pitch; yaw / body / freestanding are left to the builder AA so the
    -- fake angle is never turned left/right by flick. Rendered via apply_native_settings.
    local pv = flick_pitch_value(menu, cmd)
    pcall(function()
      local s = Class.util.antiaim.current_settings
      if pv == nil then
        s.pitch.mode = "Off"
        s.pitch.value = 0
      else
        s.pitch.mode = "Custom"
        s.pitch.value = pv
      end
      Class.util.antiaim._force_reapply = true
    end)

    cmd.roll = 0
    pcall(function() cmd.force_defensive = (cmd.command_number % 7 == 0) end)
    return true
  end

  Class.antiaim = Class.antiaim or {}
  Class.antiaim.extended_yaw = {
    _active = false,
    _side = nil,
    _lc_active = false,
    stop = function(self)
      if self._lc_active then
        pcall(function() Class.util.break_lc_mem:restore() end)
        self._lc_active = false
      end
      self._active = false
      self._side = nil
    end,
    handle = function(self, cmd)
      local menu = Class.ui.menu
        and Class.ui.menu.antiaim_tab
        and Class.ui.menu.antiaim_tab.additional
        and Class.ui.menu.antiaim_tab.additional.exploits
      if not menu or not menu.extended_yaw or not menu.extended_yaw:get() then
        self:stop()
        return
      end
      if not read_bind(menu) then
        self:stop()
        return
      end

      local local_player = entity.get_local_player()
      if not local_player or not entity.is_alive(local_player) then
        self:stop()
        return
      end
      if is_ladder(local_player) or is_grenade_weapon(local_player) then
        self:stop()
        return
      end
      -- Keep native E / defuse behaviour.
      if cmd.in_use == 1 then
        self:stop()
        return
      end

      self._active = true

      local invert = false
      pcall(function() invert = menu.inverter:get() and true or false end)
      local sel = read_manual(menu)
      local m_left, m_right = (sel == 1), (sel == 2)

      -- Target tune (Persistence menu, per side): native Yaw 180+/-90 manuals, Body Static
      -- +/-60 (back/left +, right -), pitch down, LBY break. Roll stays 0 (server-checked).
      local ext_offset = 120
      pcall(function() ext_offset = menu.yaw_offset:get() or 120 end)
      local extension = ext_offset

      -- Manual facing via native "180"+value (0 back, +90 left, -90 right), per the target menu.
      local manual_offset = 0
      if m_left then manual_offset = 90 elseif m_right then manual_offset = -90 end

      local side_dir = invert and -1 or 1
      local body_dir = (m_right and -1 or 1) * side_dir
      self._side = m_right and "RIGHT" or m_left and "LEFT" or (side_dir > 0 and "RIGHT" or "LEFT")

      -- Static stack (runs last, overrides builder): yaw 180+manual, body per-side, native roll 0.
      -- Flick never owns the fake angle, so extended yaw keeps working during an exploit.
      apply_static_aa(manual_offset, body_dir * BODY_MAX, resolve_pitch(menu))

      micro_move(cmd, local_player)

      -- Roll-free twist: body desync + yaw ext + pitch down + LBY break. Roll is 0 on every
      -- command so [BypassMasive]/rollaa.sp (angles[2] on sent AND choked) never detects it.
      cmd.roll = 0
      if cmd.chokedcommands == 0 and cmd.in_attack ~= 1 then
        cmd.yaw = cmd.yaw + extension
        cmd.allow_send_packet = false
      end

      -- FFI defensive: hide the shot during exploit (GS-native equivalent of NL's trusted-wire
      -- + hidden-shot serialize). force_defensive shifts the shooting tick; break_lc deepens the
      -- choke so the real angle is not sent on the shot. Only owns break_lc when the builder's
      -- tickbase control is not already driving it, and restores it on release.
      local defensive = false
      pcall(function() defensive = menu.defensive:get() and true or false end)
      if defensive then
        pcall(function() cmd.force_defensive = true end)
        local tickbase_driven = false
        pcall(function()
          tickbase_driven = Class.ui.menu.antiaim_tab.additional.fakelag.tickbase_enabled:get() and true or false
        end)
        if not tickbase_driven and Class.util.break_lc_mem then
          local limit = 16
          pcall(function() limit = menu.defensive_ticks:get() or 16 end)
          pcall(function() Class.util.break_lc_mem:set_limit(limit) end)
          self._lc_active = true
        elseif self._lc_active then
          pcall(function() Class.util.break_lc_mem:restore() end)
          self._lc_active = false
        end
      elseif self._lc_active then
        pcall(function() Class.util.break_lc_mem:restore() end)
        self._lc_active = false
      end
    end,
    shutdown = function(self)
      self:stop()
    end,
  }

  -- Independent flick exploit: not gated by Extended Yaw / its bind. Applied inside the
  -- builder (update_antiaim) by writing current_settings pitch only, so apply_native_settings
  -- renders it consistently with the builder. Yaw stays with the AA / extended yaw.
  Class.antiaim.flick_exploit = {
    _active = false,
    handle = function(self, cmd)
      self._active = false
      if not cmd then return end
      local menu = Class.ui.menu
        and Class.ui.menu.antiaim_tab
        and Class.ui.menu.antiaim_tab.additional
        and Class.ui.menu.antiaim_tab.additional.exploits
      if not menu or not menu.flick or not menu.flick:get() then return end
      local lp = entity.get_local_player()
      if not lp or not entity.is_alive(lp) then return end
      if is_ladder(lp) or is_grenade_weapon(lp) then return end
      if cmd.in_use == 1 then return end
      if flick_run(cmd, menu, lp) then
        self._active = true
      end
    end,
    shutdown = function(self)
      self._active = false
    end,
  }

  client.set_event_callback("paint", function()
    local fl = Class.antiaim.flick_exploit
    if not fl or not fl._active then return end
    renderer.indicator(214, 190, 115, 255, "FLICK")
  end)

  client.set_event_callback("paint", function()
    local eyb = Class.antiaim.extended_yaw
    if not eyb._active then return end
    local menu = Class.ui.menu
      and Class.ui.menu.antiaim_tab
      and Class.ui.menu.antiaim_tab.additional
      and Class.ui.menu.antiaim_tab.additional.exploits
    if not menu or not menu.extended_yaw or not menu.extended_yaw:get() then return end
    if eyb._side then
      renderer.indicator(214, 190, 115, 255, eyb._side)
    end
    local invert = false
    pcall(function() invert = menu.inverter:get() and true or false end)
    if invert then
      renderer.indicator(214, 190, 115, 255, "INV")
    end
  end)
end

-- Defensive anti-aim (native, emberlash-style feature set adapted to our pipeline). During a real
-- exploit shift it renders a full defensive preset: yaw types + offset/randomize, L/R addition,
-- yaw jitter, body desync (own side scheduler + delay), pitch types. force_defensive is NOT touched.
-- Rendered through current_settings + apply_native_settings.
do
  local da_last_fire = -100000
  local da_side = 1
  local da_sent = 0
  local da_last_switch = 0
  local da_phase = 0
  local da_way_idx = 1
  local da_prev_shift = false
  -- Randomize caches refreshed once per sent packet (stable between chokes, no per-tick noise).
  local da_r = { yaw = 0, left = 0, right = 0, jitter = 0, pitch = 0, bl = 0, br = 0 }

  local function da_menu()
    return Class.ui.menu and Class.ui.menu.antiaim_tab
      and Class.ui.menu.antiaim_tab.additional
      and Class.ui.menu.antiaim_tab.additional.defensive_aa
  end

  local function da_is_ladder(ent)
    return (entity.get_prop(ent, "m_MoveType") or 0) == 9
  end

  local function da_is_grenade(lp)
    local weapon = entity.get_player_weapon(lp)
    if not weapon then return false end
    local cls = entity.get_classname(weapon) or ""
    if cls:find("Grenade", 1, true) then return true end
    local idx = entity.get_prop(weapon, "m_iItemDefinitionIndex")
    if type(idx) == "number" then
      idx = bit.band(idx, 0xFFFF)
      if idx >= 43 and idx <= 48 then return true end
    end
    return false
  end

  local function da_get(control, default)
    local v = default
    pcall(function() v = control:get() end)
    if v == nil then v = default end
    return v
  end

  local function da_norm(angle)
    angle = tonumber(angle) or 0
    while angle > 180 do angle = angle - 360 end
    while angle < -180 do angle = angle + 360 end
    return angle
  end

  local function da_real_shift()
    local s = false
    pcall(function()
      if antiaim_funcs and type(antiaim_funcs.get_tickbase_shifting) == "function" then
        local v = tonumber(antiaim_funcs.get_tickbase_shifting())
        if v and v ~= 0 then s = true end
      end
    end)
    return s
  end

  local function da_ref_on(ref)
    local on = false
    pcall(function()
      if ref and ref[1] then on = ui.get(ref[1]) and true or false end
    end)
    return on
  end

  -- Trigger flags: defensive only fires on a REAL tickbase shift (DT/HS) or an actual shot,
  -- never just because the exploit hotkey is held. No selection falls back to DT+HS.
  local function da_triggered(m)
    local trig = m.triggers
    local sel_dt, sel_hs, sel_shot = false, false, false
    pcall(function()
      sel_dt = trig:get("Double Tap") and true or false
      sel_hs = trig:get("Hide Shots") and true or false
      sel_shot = trig:get("On Shot") and true or false
    end)
    if not sel_dt and not sel_hs and not sel_shot then sel_dt, sel_hs = true, true end
    if sel_shot and (globals.tickcount() - da_last_fire) <= 8 then return true end
    if da_real_shift() then
      if sel_dt and da_ref_on(Class.util.reference.rage_double_tap) then return true end
      if sel_hs and da_ref_on(Class.util.reference.aa_hideshots) then return true end
    end
    return false
  end

  local function da_clamp(v, lo, hi)
    v = tonumber(v) or 0
    if v < lo then return lo elseif v > hi then return hi end
    return v
  end
  local function da_mag(offset, lo, hi) return da_clamp(math.abs(tonumber(offset) or 0), lo, hi) end
  local function da_rand(lo, hi)
    lo, hi = math.min(lo, hi), math.max(lo, hi)
    return math.random(lo, hi)
  end
  local function da_rnd_amt(pct, hi) return math.floor(da_clamp(pct, 0, 100) * hi / 100 + 0.5) end

  local function da_refresh_random(m)
    local function r(pct, hi) local a = da_rnd_amt(pct, hi); return da_rand(-a, a) end
    da_r.yaw = r(da_get(m.yaw_offset_randomize, 0), 127)
    da_r.left = r(da_get(m.left_offset_randomize, 0), 139)
    da_r.right = r(da_get(m.right_offset_randomize, 0), 149)
    da_r.jitter = r(da_get(m.jitter_offset_randomize, 0), 15)
    da_r.pitch = r(da_get(m.pitch_offset_randomize, 0), 113)
    da_r.bl = r(da_get(m.body_left_randomize, 0), 60)
    da_r.br = r(da_get(m.body_right_randomize, 0), 60)
  end

  local function da_delay_fields(m, side)
    local suffix = ""
    if da_get(m.l_r_delay, false) then suffix = (side < 0) and "_left" or "_right" end
    return da_get(m["delay_value" .. suffix], 1), da_get(m["delay_min" .. suffix], 1),
      da_get(m["delay_max" .. suffix], 1), da_get(m["delay_variability" .. suffix], 0)
  end

  local function da_compute_delay(m, side)
    local mode = da_get(m.delay, "Static")
    if mode == "Off" then return 1 end
    local value, mn, mx, var = da_delay_fields(m, side)
    mn, mx = math.min(mn, mx), math.max(mn, mx)
    if mode == "Static" then return da_clamp(value, 1, 22) end
    if mode == "Random" then return da_clamp(da_rand(mn, mx), 1, 22) end
    if mode == "Smart" then
      local window = math.floor(7 * var / 200 + 0.5)
      local best = value
      for _, c in ipairs({ 1, 3, 5, 7, 10, 15, 20 }) do
        if math.abs(c - value) <= window then best = c break end
      end
      return da_clamp(best, 1, 22)
    end
    if mode == "Fluctuate" then
      local mid, half = (mn + mx) / 2, (mx - mn) / 2
      return da_clamp(math.floor(mid + math.sin(globals.curtime() * 2) * half + 0.5), 1, 22)
    end
    if mode == "Ways" then
      local v = ({ mn, value, mx })[da_clamp(da_way_idx, 1, 3)]
      da_way_idx = (da_way_idx % 3) + 1
      return da_clamp(v, 1, 22)
    end
    return da_clamp(value, 1, 22)
  end

  -- Own side scheduler: counts sent packets only, flips desync side by the defensive delay.
  local function da_scheduler(m, cmd)
    if cmd.chokedcommands ~= 0 then return end
    da_sent = da_sent + 1
    da_phase = da_phase + 1
    if da_sent - da_last_switch >= da_compute_delay(m, da_side) then
      da_side = -da_side
      da_last_switch = da_sent
      da_phase = 0
    end
    da_refresh_random(m)
  end

  local function da_jitter(m)
    local mode = da_get(m.yaw_jitter, "Off")
    if mode == "Off" then return 0 end
    local mg = math.abs(da_get(m.jitter_offset, 0))
    local speed = da_get(m.jitter_speed, 10)
    local ph = da_phase
    local v = 0
    if mode == "Offset" then v = -mg
    elseif mode == "Center" then v = da_side * mg
    elseif mode == "Random" then v = da_rand(-mg, mg)
    elseif mode == "Skitter" then
      v = ({ -mg, 0.45 * mg, -0.2 * mg, mg, -0.65 * mg, 0.15 * mg })[(ph % 6) + 1]
    elseif mode == "Spin" then v = math.sin(math.rad(globals.curtime() * speed * 18)) * mg
    elseif mode == "Multi-way" then
      local ways = da_clamp(da_get(m.jitter_ways, 3), 3, 8)
      local idx = (ph % ways) + 1
      v = -mg + (idx - 1) * 2 * mg / (ways - 1)
    end
    return v + da_r.jitter
  end

  local function da_yaw_base(m)
    local t = da_get(m.yaw_type, "Custom")
    local off = da_get(m.yaw_offset, 0)
    local speed = da_get(m.yaw_speed, 10)
    local ph = da_phase
    if t == "Custom" then return off end
    if t == "Cross switch" then return da_side * da_mag(off, 95, 166) end
    if t == "Three point" then
      local mg = da_mag(off, 120, 180)
      return ({ -mg, 0, mg })[(ph % 3) + 1]
    end
    if t == "Wide switch" then return da_side * da_mag(off, 160, 180) end
    if t == "Spin" then return da_norm(off + ph * 38 * (speed * 0.1)) end
    if t == "Distortion" then return math.sin(math.rad(globals.curtime() * speed * 18)) * da_mag(off, 90, 180) end
    if t == "Random" then return da_rand(-180, 180) end
    return off
  end

  local function da_yaw_total(m)
    local total = da_yaw_base(m) + da_r.yaw
    if da_get(m.l_r_addition, false) then
      if da_side < 0 then total = total + da_get(m.left_offset, 0) + da_r.left
      else total = total + da_get(m.right_offset, 0) + da_r.right end
    end
    return da_norm(total + da_jitter(m))
  end

  local function da_pitch_value(m)
    local t = da_get(m.pitch_type, "Off")
    if t == "Off" then return nil end
    local off = da_get(m.pitch_offset, 0)
    local speed = da_get(m.pitch_speed, 10)
    local ph = da_phase
    local v
    if t == "Custom" then v = off
    elseif t == "Cross switch" then v = da_side * da_mag(off, 45, 89)
    elseif t == "Three point" then
      local mg = da_mag(off, 45, 89); v = ({ mg, 0, -mg })[(ph % 3) + 1]
    elseif t == "Five point" then
      local mg = da_mag(off, 80, 89); v = ({ mg, 0.5 * mg, 0, -0.5 * mg, -mg })[(ph % 5) + 1]
    elseif t == "Pendulum" then v = -da_mag(off, 80, 89) * math.sin(math.rad(ph * 18 * speed * 0.1))
    elseif t == "Edge sweep" then v = -69 - 19 * math.sin(math.rad(ph * 18 * speed * 0.1))
    elseif t == "Random" then v = da_rand(-89, 89)
    else v = off end
    return da_clamp(v + da_r.pitch, -89, 89)
  end

  local function da_apply_body(s, m)
    local mode = da_get(m.body_yaw, "Keep")
    if mode == "Keep" then return end
    if mode == "Off" then
      s.body_yaw.mode = "Off"; s.body_yaw.value = 0; return
    end
    local left = da_clamp(da_get(m.body_left, 60) + da_r.bl, 0, 60)
    local right = da_clamp(da_get(m.body_right, 60) + da_r.br, 0, 60)
    s.body_yaw.mode = "Static"
    if mode == "Jitter" then
      s.body_yaw.value = (da_side < 0) and -left or right
    else
      s.body_yaw.value = (da_side < 0) and -right or right
    end
  end

  Class.antiaim = Class.antiaim or {}
  Class.antiaim.defensive_aa = {
    _active = false,
    handle = function(self, cmd)
      self._active = false
      if not cmd then return end
      local m = da_menu()
      if not m or not da_get(m.enabled, false) then return end
      -- Builder manual direction has priority, same as the aesthetic pipeline.
      if (tonumber(Class.util.antiaim.manual_direction) or 0) ~= 0 then return end
      local lp = entity.get_local_player()
      if not lp or not entity.is_alive(lp) then return end
      if da_is_ladder(lp) or da_is_grenade(lp) then return end
      if cmd.in_use == 1 then return end
      if Class.misc.duck_peek_assist_fix and Class.misc.duck_peek_assist_fix.altered then return end
      if not da_triggered(m) then da_prev_shift = false; return end
      da_scheduler(m, cmd)
      da_prev_shift = true
      pcall(function()
        local s = Class.util.antiaim.current_settings
        -- Full native defensive preset rendered as 180 + computed yaw offset (jitter baked in),
        -- own side scheduler drives the body desync. force_defensive is NOT touched.
        s.yaw.base = "At targets"
        s.yaw.mode = "180"
        s.yaw.value = da_yaw_total(m)
        s.yaw.modifier.mode = "Off"
        s.yaw.modifier.value = 0
        s.freestanding.enabled = false
        da_apply_body(s, m)
        local pv = da_pitch_value(m)
        if pv ~= nil then
          s.pitch.mode = "Custom"
          s.pitch.value = pv
        end
        Class.util.antiaim._force_reapply = true
      end)
      self._active = true
    end,
    shutdown = function(self)
      self._active = false
      da_side = 1
      da_sent = 0
      da_last_switch = 0
      da_phase = 0
      da_way_idx = 1
      da_prev_shift = false
    end,
  }

  client.set_event_callback("aim_fire", function()
    da_last_fire = globals.tickcount()
  end)

  client.set_event_callback("paint", function()
    local da = Class.antiaim.defensive_aa
    if not da or not da._active then return end
    renderer.indicator(214, 190, 115, 255, "DEF AA")
  end)
end

Class.gamesense = {
 hide_shots_fakelag_fix = {
  _is_active = false,
  _saved_limit = nil,
  check_active = function(self)
    local success = false
    pcall(function()
      success = Class.ui.menu.gamesense_settings.hide_shots_fakelag_fix.enabled:get() and true or false
    end)
    if not success then return false end
    local reference = Class.util.reference
    local hideshots_active, is_fakeduck, is_doubletap = false, false, false
    pcall(function()
      local hideshots_ref = reference.aa_hideshots
      if hideshots_ref and hideshots_ref[1] and hideshots_ref[2] then
        hideshots_active = ui.get(hideshots_ref[1]) and ui.get(hideshots_ref[2])
      end
    end)
    pcall(function()
      local fake_duck_ref = reference.rage_fake_duck
      if fake_duck_ref and fake_duck_ref[1] then is_fakeduck = ui.get(fake_duck_ref[1]) end
    end)
    pcall(function()
      local double_tap_ref = reference.rage_double_tap
      if double_tap_ref and double_tap_ref[1] and double_tap_ref[2] then
        is_doubletap = ui.get(double_tap_ref[1]) and ui.get(double_tap_ref[2])
      end
    end)
    return hideshots_active and not is_fakeduck and not is_doubletap
  end,
  apply_settings = function(self)
    local reference = Class.util.reference.aa_fakelag_limit
    if not reference or not reference[1] then return end
    if not self._is_active then
      local ok, value = pcall(ui.get, reference[1])
      if not ok then return end
      self._saved_limit = value
      self._is_active = true
    end
    pcall(ui.set, reference[1], 1)
  end,
  restore_settings = function(self)
    if not self._is_active then return end
    local reference = Class.util.reference.aa_fakelag_limit
    if reference and reference[1] and self._saved_limit ~= nil then
      pcall(ui.set, reference[1], self._saved_limit)
    end
    self._saved_limit = nil
    self._is_active = false
  end,
  handle = function(self)
    if self:check_active() then
      self:apply_settings()
    else
      self:restore_settings()
    end
  end,
  on_paint_ui = function(self)
    self:handle()
  end,
 },
 force_shot = {
  _active = false,
  _saved = nil,
  _refs = nil,
  _state = "idle",
  _applied_hc = nil,
  _smooth_t = nil,
  _scan_cache = 0,
  _scan_at = 0,
  _resolve_refs = function(self)
    if self._refs ~= nil then return self._refs end
    local refs = {
      hit_chance = nil,
      multipoint_scale = nil,
      safe_point = nil,
      delay_shot = nil,
    }
    pcall(function() refs.hit_chance = ui.reference("RAGE", "Aimbot", "Minimum hit chance") end)
    pcall(function() refs.multipoint_scale = ui.reference("RAGE", "Aimbot", "Multi-point scale") end)
    pcall(function() refs.safe_point = ui.reference("RAGE", "Aimbot", "Force safe point") end)
    pcall(function() refs.delay_shot = ui.reference("RAGE", "Other", "Delay shot") end)
    pcall(function() refs.min_damage = ui.reference("RAGE", "Aimbot", "Minimum damage") end)
    self._refs = refs
    return refs
  end,
  _menu = function(self)
    return Class.ui.menu and Class.ui.menu.gamesense_settings and Class.ui.menu.gamesense_settings.force_shot
  end,
  _hotkey_active = function(self, menu)
    local hk = menu and menu.hotkey
    if not hk then return true end
    if type(hk) == "number" then
      -- native inline hotkey reference
      local ok, active = pcall(ui.get, hk)
      if ok then return active and true or false end
      return true
    end
    if hk.ref then
      local ok, active = pcall(ui.get, hk.ref)
      if ok then
        if type(active) == "boolean" then return active end
      end
    end
    local ok, value = pcall(function() return hk:get() end)
    if ok then
      if type(value) == "boolean" then return value end
      if type(value) == "number" then return value ~= 0 end
    end
    -- unbound / always-on style controls still allow the feature when enabled
    return true
  end,
  _weapon_index = function(self, weapon)
    if not weapon then return nil end
    local idx = entity.get_prop(weapon, "m_iItemDefinitionIndex")
    if type(idx) == "number" then return bit.band(idx, 0xFFFF) end
    return nil
  end,
  _should_skip_weapon = function(self, weapon)
    if not weapon then return true end
    local idx = self:_weapon_index(weapon)
    if idx then
      if idx == 31 or idx == 49 then return true end
      if idx >= 43 and idx <= 48 then return true end
      if idx >= 500 and idx < 600 then return true end
    end
    local cls = entity.get_classname(weapon) or ""
    if cls == "CKnife" or cls == "CWeaponTaser" or cls == "CC4" then return true end
    if cls:find("Grenade", 1, true) or cls:find("Knife", 1, true) then return true end
    return false
  end,
  _motion_state = function(self, local_player)
    local vx, vy = entity.get_prop(local_player, "m_vecVelocity")
    vx, vy = vx or 0, vy or 0
    local speed = math.sqrt(vx * vx + vy * vy)
    local flags = entity.get_prop(local_player, "m_fFlags") or 0
    local on_ground = bit.band(flags, 1) ~= 0
    local ducking = bit.band(flags, 2) ~= 0 or bit.band(flags, 4) ~= 0
    if not on_ground then
      return "air", speed, ducking
    end
    if ducking then
      return "duck", speed, true
    end
    if speed > 34 then
      return "walk", speed, false
    end
    return "stand", speed, false
  end,
  _velocity_guard = function(self, motion)
    -- The accuracy penalty lags behind acceleration: guard the readiness with
    -- a mild velocity term so a fresh fast peek never looks fully charged.
    local speed = motion.speed or 0
    return 1 - math.min(math.max((speed - 20) / 220, 0), 1) * 0.25
  end,
  _shot_scan = function(self, local_player, weapon)
    -- Physical readiness of a shot. For every exposed point of every enemy
    -- compute how well the CURRENT weapon inaccuracy covers that point at its
    -- distance: expected error radius = distance * m_fAccuracyPenalty, a
    -- point is "covered" when the error fits inside its effective size.
    -- Score: 0 = nothing shootable (we / every enemy behind a wall), <1 =
    -- partial cover or a loose shot ("unsafe" quality), 1 = a clean point is
    -- exposed with the current spread. Points that cannot deliver the rage
    -- min damage do not count as available.
    local now = globals.realtime() or 0
    if now - self._scan_at < 0.1 then return self._scan_cache end
    local score = 0
    repeat
      if not local_player or not weapon then break end
      local eye_x, eye_y, eye_z = client.eye_position()
      if not eye_x then break end
      local penalty = entity.get_prop(weapon, "m_fAccuracyPenalty")
      if type(penalty) ~= "number" or penalty <= 0 then penalty = 0.002 end
      local refs = self:_resolve_refs()
      local min_damage = self:_read(refs.min_damage)
      if type(min_damage) ~= "number" or min_damage < 0 then min_damage = nil end
      local enemies = entity.get_players(true)
      if type(enemies) ~= "table" then break end
      -- hitbox ids per this script's groups: 0 head, 5 chest, 2 pelvis
      local points = {
        { hitbox = 0, weight = 1, size = 5 },
        { hitbox = 5, weight = 0.85, size = 12 },
        { hitbox = 2, weight = 0.7, size = 10 },
      }
      for i = 1, #enemies do
        local ox, oy, oz = entity.get_prop(enemies[i], "m_vecOrigin")
        if ox and oy then
          local dx, dy = ox - eye_x, oy - eye_y
          if dx * dx + dy * dy < 17640000 then -- ~4200 units
            for j = 1, #points do
              local hx, hy, hz = entity.hitbox_position(enemies[i], points[j].hitbox)
              if hx then
                local ok, _, dmg = pcall(client.trace_bullet,
                  local_player, eye_x, eye_y, eye_z, hx, hy, hz, true)
                if ok and type(dmg) == "number" and dmg > 0
                   and (min_damage == nil or dmg >= min_damage) then
                  local ex, ey, ez = hx - eye_x, hy - eye_y, hz - eye_z
                  local dist = math.sqrt(ex * ex + ey * ey + ez * ez)
                  -- how much of the point the current spread covers
                  local coverage = points[j].size / (dist * penalty)
                  if coverage > 1 then coverage = 1 end
                  local point_score = coverage * points[j].weight
                  if point_score > score then score = point_score end
                  if score >= 1 then break end
                end
              end
            end
            if score >= 1 then break end
          end
        end
      end
    until true
    self._scan_cache = score
    self._scan_at = now
    return score
  end,
  _force_values = function(self, menu, motion, weapon, local_player)
    -- Hit chance is anchored to the user threshold: fully ready -> threshold,
    -- and the less ready the weapon is, the higher the gate (the ragebot then
    -- waits for a cleaner shot instead of firing low-chance bullets).
    local threshold = 25
    pcall(function() threshold = tonumber(menu.hit_chance:get()) or 25 end)
    if threshold < 0 then threshold = 0 elseif threshold > 100 then threshold = 100 end
    local t = self:_shot_scan(local_player, weapon)
    -- Mild velocity guard on top: covers the frames where the penalty has
    -- not caught up with a fresh acceleration yet.
    t = t * self:_velocity_guard(motion)
    -- Asymmetric smoothing: charge up faster than it decays, so the shot is
    -- taken as soon as the window opens without overshooting on the way out.
    local prev = self._smooth_t
    if type(prev) == "number" then
      t = prev + (t - prev) * (t > prev and 0.5 or 0.3)
    end
    self._smooth_t = t
    local in_air = motion.state == "air"
    local hit_chance = threshold + math.floor((1 - t) * threshold * (in_air and 2 or 1) + 0.5)
    if hit_chance > 100 then hit_chance = 100 end
    local multipoint = 100 - math.floor((1 - t) * (in_air and 40 or 20) + 0.5)
    return hit_chance, multipoint, t
  end,
  _read = function(self, ref)
    if not ref then return nil end
    local ok, value = pcall(ui.get, ref)
    if ok then return value end
    return nil
  end,
  _write = function(self, ref, value)
    if not ref or value == nil then return end
    pcall(ui.set, ref, value)
  end,
  _capture = function(self, refs)
    return {
      hit_chance = self:_read(refs.hit_chance),
      multipoint_scale = self:_read(refs.multipoint_scale),
      safe_point = self:_read(refs.safe_point),
      delay_shot = self:_read(refs.delay_shot),
    }
  end,
  _apply = function(self, refs, hit_chance, multipoint, settled_ready)
    -- Safe points / delay shot are disabled only once the shot is genuinely
    -- ready (t >= 0.55); while the weapon is still "warming up" the aimbot
    -- keeps its own safety settings.
    if settled_ready then
      if refs.safe_point then
        local current = self:_read(refs.safe_point)
        if current ~= "Off" and current ~= "Default" then
          if not pcall(ui.set, refs.safe_point, "Off") then
            pcall(ui.set, refs.safe_point, "Default")
          end
        end
      end
      self:_write(refs.delay_shot, false)
    end
  end,
  restore = function(self)
    if not self._active then
      self._state = "idle"
      self._applied_hc = nil
      return
    end
    local refs = self:_resolve_refs()
    local saved = self._saved or {}
    self:_write(refs.hit_chance, saved.hit_chance)
    self:_write(refs.multipoint_scale, saved.multipoint_scale)
    self:_write(refs.safe_point, saved.safe_point)
    self:_write(refs.delay_shot, saved.delay_shot)
    self._saved = nil
    self._active = false
    self._state = "idle"
    self._applied_hc = nil
    self._smooth_t = nil
    self._scan_cache = 0
    self._scan_at = 0
  end,
  handle = function(self)
    local menu = self:_menu()
    if not menu or not menu.enabled or not menu.enabled:get() then
      self:restore()
      return
    end
    if not self:_hotkey_active(menu) then
      self:restore()
      return
    end
    if globals.mapname() == nil then
      self:restore()
      return
    end
    local local_player = entity.get_local_player()
    if not local_player or not entity.is_alive(local_player) then
      self:restore()
      return
    end
    local weapon = entity.get_player_weapon(local_player)
    if self:_should_skip_weapon(weapon) then
      self:restore()
      return
    end
    local state, speed, ducking = self:_motion_state(local_player)
    local motion = { state = state, speed = speed, ducking = ducking }
    local work_in_air = true
    pcall(function() work_in_air = menu.work_in_air:get() and true or false end)
    if motion.state == "air" and not work_in_air then
      self:restore()
      return
    end
    -- On the ground the overrides stay active while the key is held: as the
    -- weapon settles the gate ramps down to the user threshold instead of
    -- toggling on/off at a fixed settled mark.
    local refs = self:_resolve_refs()
    if not refs.hit_chance and not refs.multipoint_scale then
      return
    end
    local hit_chance, multipoint, readiness = self:_force_values(menu, motion, weapon, local_player)
    if not self._active then
      self._saved = self:_capture(refs)
      self._active = true
    end
    self:_apply(refs, hit_chance, multipoint, readiness >= 0.55)
    self:_write(refs.hit_chance, hit_chance)
    self:_write(refs.multipoint_scale, multipoint)
    self._state = state
    self._applied_hc = hit_chance
  end,
  _charge = 0,
  _charge_amount = function(self, local_player, weapon)
    if not local_player or not weapon then return 0 end
    if self:_should_skip_weapon(weapon) then return 0 end
    local state, speed = self:_motion_state(local_player)
    local menu = self:_menu()
    local work_in_air = true
    pcall(function() work_in_air = menu and menu.work_in_air:get() and true or false end)
    if state == "air" and not work_in_air then return 0 end
    local motion = { state = state, speed = speed }
    local t = self:_shot_scan(local_player, weapon)
    t = t * self:_velocity_guard(motion)
    return t
  end,
  render_indicator = function(self)
    local menu = self:_menu()
    if not menu or not menu.enabled or not menu.enabled:get() then
      self._charge = 0
      return
    end
    local show = true
    pcall(function() show = menu.indicator:get() and true or false end)
    if not show then
      self._charge = 0
      return
    end
    if not self:_hotkey_active(menu) then
      self._charge = 0
      return
    end
    local local_player = entity.get_local_player()
    if not local_player or not entity.is_alive(local_player) then
      self._charge = 0
      return
    end

    local weapon = entity.get_player_weapon(local_player)
    local target = self:_charge_amount(local_player, weapon)
    if self._active then target = 1 end
    local frame_time = 0.015
    pcall(function() frame_time = math.max(0.0, math.min(0.05, globals.frametime())) end)
    local blend = math.min(1, frame_time * 14)
    self._charge = (self._charge or 0) + (target - (self._charge or 0)) * blend
    if math.abs(target - self._charge) < 0.002 then self._charge = target end

    local r, g, b, a = 235, 235, 235, 255
    pcall(function()
      r, g, b, a = menu.indicator_color:get()
    end)
    a = math.max(0, math.min(255, tonumber(a) or 255))
    if a < 1 then return end

    local charge = math.max(0, math.min(1, self._charge or 0))
    local text_a = a
    if not self._active then
      text_a = math.floor(a * (0.45 + charge * 0.55) + 0.5)
    end

    -- Native future-indicator row. Leading spaces reserve room for the charge ring
    -- so the ring and FORCE text stay on one line without overlapping.
    local ind_y = nil
    local ok_ind, ret = pcall(renderer.indicator, r, g, b, text_a, "    FORCE")
    if ok_ind and type(ret) == "number" then
      ind_y = ret
    end

    local screen_w, screen_h = client.screen_size()
    local radius = 9
    local thickness = 3
    -- GS indicators start near the left edge; ring sits in the reserved space.
    local x = 26
    local y
    if ind_y then
      y = ind_y + 17
    else
      y = screen_h - 80
    end
    local bg_a = math.floor(a * 0.30 + 0.5)
    local ring_a = math.floor(a * (0.50 + charge * 0.50) + 0.5)

    pcall(renderer.circle_outline, x, y, 15, 15, 15, math.floor(a * 0.65 + 0.5), radius, 0, 1, thickness + 1)
    pcall(renderer.circle_outline, x, y, r, g, b, bg_a, radius, 0, 1, thickness)
    if charge > 0.02 then
      pcall(renderer.circle_outline, x, y, r, g, b, ring_a, radius, -90, charge, thickness)
    end
  end,

 },

_mem = {
 read = function(addr, length)
   local output = {}
   local success = pcall(function()
     local ptr = ffi.cast("uint8_t*", addr)
     for index = 1, length do output[index] = ptr[index - 1] end
   end)
   if not success then return nil end
   return output
 end,
 write = function(addr, bytes)
   if not addr or type(bytes) ~= "table" or #bytes == 0 then return false end
   local success, wrote = pcall(function()
     local ptr = ffi.cast("uint8_t*", addr)
     local old = ffi.new("unsigned long[1]")
     local size = #bytes
     local kernel = ffi.load("kernel32")
     local vp_ok, vp_result = pcall(kernel.VirtualProtect, ptr, size, 0x40, old)
     if not vp_ok or vp_result == 0 then return false end
     for index = 1, size do
       ptr[index - 1] = bytes[index]
     end
     pcall(kernel.VirtualProtect, ptr, size, old[0], old)
     return true
   end)
   return success and wrote == true
 end,
 match = function(a, b)
   if not a or not b or #a ~= #b then return false end
   for index = 1, #a do if a[index] ~= b[index] then return false end end
   return true
 end,
},
animation_flag_preservation = make_native_literal_fix(
 "Animation flag preservation",
 "C7 04 18 04 00 00 00 E9 ? ? ? ?",
 0,
 {199, 4, 24, 4, 0, 0, 0},
 {131, 12, 24, 4, 144, 144, 144}
),
accurate_quick_stop = {
 _active = false,
 _sites = nil,
 _last_attempt = -10,
 _specs = {
  {
   name = "first Early-result admission",
   pattern = "\xF7\x06\x00\x04\x00\x00\x0F\x85\xCC\xCC\xCC\xCC\x8B\x56\x0C\x85\xD2\x74\xCC",
   offset = 2,
   original = {0x00, 0x04, 0x00, 0x00},
   patched = {0x00, 0x04, 0x01, 0x00},
  },
  {
   name = "second Early-result admission",
   pattern = "\xF7\x06\x00\x04\x00\x00\x0F\x85\xCC\xCC\xCC\xCC\x8B\x4E\x0C\x89\x8C\x24\xC8\x00\x00\x00",
   offset = 2,
   original = {0x00, 0x04, 0x00, 0x00},
   patched = {0x00, 0x04, 0x01, 0x00},
  },
  {
   name = "Double Tap motion-policy fidelity",
   pattern = "\x83\xC8\x08\x83\x0D\xCC\xCC\xCC\xCC\x04\xA3\xCC\xCC\xCC\xCC\x8B\x8C\x24\x80\x00\x00\x00",
   offset = 9,
   original = {0x04},
   patched = {0x00},
  },
 },
 _resolve = function(self)
  local mem = Class.gamesense._mem
  local sites, occupied = {}, {}
  for i = 1, #self._specs do
   local spec = self._specs[i]
   local ok, match = pcall(client.find_signature, "client.dll", spec.pattern)
   if not ok or not match then return nil end
   local address
   local number_ok, numeric = pcall(tonumber, match)
   if number_ok then address = numeric end
   if not address then
    local cast_ok, casted = pcall(function()
     return tonumber(ffi.cast("uintptr_t", match))
    end)
    if not cast_ok then return nil end
    address = casted
   end
   if not address or address == 0 then return nil end
   local patch_address = address + spec.offset
   if occupied[patch_address] then return nil end
   occupied[patch_address] = true
   local current = mem.read(patch_address, #spec.original)
   local changed
   if mem.match(current, spec.original) then
    changed = true
   elseif mem.match(current, spec.patched) then
    changed = false
   else
    return nil
   end
   sites[#sites + 1] = {
    name = spec.name,
    address = patch_address,
    original = spec.original,
    patched = spec.patched,
    changed = changed,
   }
  end
  return sites
 end,
 apply = function(self)
  if self._active then return true end
  local sites = self:_resolve()
  if not sites then return false end
  local mem = Class.gamesense._mem
  local written = {}
  for i = 1, #sites do
   local site = sites[i]
   if site.changed then
    if not mem.write(site.address, site.patched) then
     for j = #written, 1, -1 do
      local applied = written[j]
      local current = mem.read(applied.address, #applied.patched)
      if mem.match(current, applied.patched) then
       mem.write(applied.address, applied.original)
      end
     end
     return false
    end
    written[#written + 1] = site
   end
  end
  self._sites = sites
  self._active = true
  return true
 end,
 restore = function(self)
  if not self._sites then
   self._active = false
   return
  end
  local mem = Class.gamesense._mem
  for i = #self._sites, 1, -1 do
   local site = self._sites[i]
   if site.changed then
    local current = mem.read(site.address, #site.patched)
    if mem.match(current, site.patched) then
     mem.write(site.address, site.original)
    end
   end
  end
  self._sites = nil
  self._active = false
 end,
 handle = function(self)
  local menu = Class.ui.menu.gamesense_settings.accurate_quick_stop
  local on = false
  pcall(function() on = menu.enabled:get() and true or false end)
  if not on or globals.mapname() == nil then
   self:restore()
   return
  end
  if self._active then return end
  local now = globals.realtime() or 0
  if now - self._last_attempt < 1 then return end
  self._last_attempt = now
  self:apply()
 end,
},
shot_delay_fix = {
 _active = false,
 _patches = {
  { address = 0x433ED5BD, original = { 0x75, 0x07 }, patched = { 0xEB, 0x07 } },
  { address = 0x433ED757, original = { 0x0F, 0x2F, 0x15, 0x58, 0x27, 0x47, 0x43 }, patched = { 0x0F, 0x2F, 0x15, 0x6C, 0xEE, 0x46, 0x43 } },
  { address = 0x4335BAA5, original = { 0x74, 0x64 }, patched = { 0x90, 0x90 } },
 },
apply = function(self)
  if self._active then return end
  if apply_patch_set(self._patches) then
    self._active = true
  end
end,
restore = function(self)
  if self._active then
    restore_patch_set(self._patches)
    self._active = false
  end
end,
handle = function(self)
  if Class.ui.menu.gamesense_settings.shot_delay_fix.enabled:get() then
    self:apply()
  else
  self:restore()
end
end,
},
double_tap_stability_fix = {
 _active = false,
 _patches = {
  { address = 0x433ABF59, original = { 0x74, 0x13 }, patched = { 0xEB, 0x13 } },
  { address = 0x433ABFFE, original = { 0x0F, 0x85, 0x9A, 0x02, 0x00, 0x00 }, patched = { 0x0F, 0x84, 0x9A, 0x02, 0x00, 0x00 } },
  { address = 0x433AC0F7, original = { 0x0F, 0x85, 0xA1, 0x02, 0x00, 0x00 }, patched = { 0x0F, 0x84, 0xA1, 0x02, 0x00, 0x00 } },
  { address = 0x433AC167, original = { 0x0F, 0x86, 0x31, 0x01, 0x00, 0x00 }, patched = { 0xE9, 0x32, 0x01, 0x00, 0x00, 0x90 } },
  { address = 0x433ABEA5, original = { 0x0F, 0x8E, 0xF3, 0x03, 0x00, 0x00 }, patched = { 0xE9, 0xF4, 0x03, 0x00, 0x00, 0x90 } },
 },
apply = function(self)
  if self._active then return end
  if apply_patch_set(self._patches) then
    self._active = true
  end
end,
restore = function(self)
  if self._active then
    restore_patch_set(self._patches)
    self._active = false
  end
end,
handle = function(self)
  if Class.ui.menu.gamesense_settings.double_tap_stability_fix.enabled:get() then
    self:apply()
  else
  self:restore()
end
end,
},
double_tap_return_fix = {
 _active = false,
 _scope = nil,
 _button_site = nil,
 _return_site = nil,
 _button_original = nil,
 _return_original = nil,
 _button_patch = nil,
 _return_patch = nil,
 _preserve_ptr = nil,
 _last_attempt = -10,
 _signature_button = "8B 86 A8 00 00 00 33 46 7C A9 1A 06 00 00 75 ? A1 ? ? ? ? 8B 54 24 24",
 _signature_return = "0F 2F E5 72 34 8B 44 24 34 8B 54 24 24 F3 0F 10 44 24 6C 81 60 30 FF FF FD FF",
 _button_bytes = {139, 134, 168, 0, 0, 0, 51, 70, 124, 169, 26, 6, 0, 0, 117, 71},
 _return_bytes = {15, 47, 229, 114, 52},
 _ptr = function(value)
  if value == nil then return 0 end
  local ok, result = pcall(tonumber, value)
  if ok and result and result ~= 0 then return result end
  local cast_ok, cast_result = pcall(function() return tonumber(ffi.cast("uintptr_t", value)) end)
  if cast_ok then return cast_result or 0 end
  return 0
 end,
 _u32 = function(value)
  local n = bit.tobit(value)
  return string.char(
   bit.band(n, 0xFF),
   bit.band(bit.rshift(n, 8), 0xFF),
   bit.band(bit.rshift(n, 16), 0xFF),
   bit.band(bit.rshift(n, 24), 0xFF)
  )
 end,
 _jmp = function(base, offset, target)
  return "\xE9" .. Class.gamesense.double_tap_return_fix._u32(target - (base + offset + 5))
 end,
 _jcc = function(opcode, base, offset, target)
  return "\x0F" .. string.char(opcode) .. Class.gamesense.double_tap_return_fix._u32(target - (base + offset + 6))
 end,
 _bytes = function(value)
  local result = {}
  for i = 1, #value do result[i] = value:byte(i) end
  return result
 end,
 _signature_address = function(self, pattern)
  local ok, match = pcall(client.find_signature, "client.dll", pattern)
  if not ok or not match then return nil end
  local address = self._ptr(match)
  if address == 0 then return nil end
  return address
 end,
 _build_caves = function(self, scope, button_site, return_site, button_original, return_original)
  local button_cave = scope:alloc(256, {fill = 0x90})
  local return_cave = scope:alloc(128, {fill = 0x90})
  local button_address = button_cave.address
  local return_address = return_cave.address
  local preserve_address = button_address + 224

  local button_target = button_site + 16 + 0x47
  local return_target = return_site + 5 + 0x34

  local button_code = "\x80\x7E\x78\x03"
  button_code = button_code .. self._jcc(0x85, button_address, 4, button_address + 80)
  button_code = button_code .. "\x80\x3D" .. self._u32(preserve_address) .. "\x00"
  button_code = button_code .. self._jcc(0x85, button_address, 17, button_address + 64)
  button_code = button_code .. self._jmp(button_address, 23, button_address + 80)
  assert(#button_code == 28, "button cave header size mismatch")
  button_code = button_code .. string.rep("\x90", 64 - #button_code)
  button_code = button_code .. self._jmp(button_address, 64, button_site + 16)
  button_code = button_code .. string.rep("\x90", 80 - #button_code)
  button_code = button_code .. string.sub(string.char(unpack(button_original)), 1, 14)
  button_code = button_code .. self._jcc(0x85, button_address, 94, button_target)
  button_code = button_code .. self._jmp(button_address, 100, button_address + 64)
  button_code = button_code .. string.rep("\x90", 256 - #button_code)

  local return_code = "\x80\x7E\x78\x03"
  return_code = return_code .. self._jcc(0x85, return_address, 4, return_address + 64)
  return_code = return_code .. "\x80\x3D" .. self._u32(preserve_address) .. "\x00"
  return_code = return_code .. self._jcc(0x84, return_address, 17, return_target)
  return_code = return_code .. self._jmp(return_address, 23, return_site + 5)
  assert(#return_code == 28, "return cave header size mismatch")
  return_code = return_code .. string.rep("\x90", 64 - #return_code)
  return_code = return_code .. "\x0F\x2F\xE5"
  return_code = return_code .. self._jcc(0x82, return_address, 67, return_target)
  return_code = return_code .. self._jmp(return_address, 73, return_site + 5)
  return_code = return_code .. string.rep("\x90", 128 - #return_code)

  button_cave:write(0, button_code, #button_code)
  return_cave:write(0, return_code, #return_code)
  self._preserve_ptr = preserve_address
  pcall(function() ffi.cast("uint8_t*", preserve_address)[0] = 0 end)

  local button_patch = "\xE9" .. self._u32(button_address - (button_site + 5)) .. string.rep("\x90", 11)
  local return_patch = "\xE9" .. self._u32(return_address - (return_site + 5))
  return button_patch, return_patch
 end,
 apply = function(self)
  if self._active then return true end
  local mem = Class.gamesense._mem
  local button_site = self:_signature_address(self._signature_button)
  local return_site = self:_signature_address(self._signature_return)
  if not button_site or not return_site or button_site == return_site then return false end

  local button_original = mem.read(button_site, 16)
  local return_original = mem.read(return_site, 5)
  if not mem.match(button_original, self._button_bytes) or not mem.match(return_original, self._return_bytes) then
   return false
  end
  local button_disp = button_original[16]
  if button_disp >= 128 then button_disp = button_disp - 256 end
  if button_site + 16 + button_disp ~= button_site + 87 or return_original[5] ~= 0x34 then
   return false
  end

  local memory_ok, memory = pcall(require, "lib/memory")
  if not memory_ok or not memory or type(memory.scope) ~= "function" then return false end
  local scope_ok, scope = pcall(memory.scope, "Emberlash Double Tap Return Fix")
  if not scope_ok or not scope then return false end
  local ok, button_patch, return_patch = pcall(function()
   local bp, rp = self:_build_caves(scope, button_site, return_site, button_original, return_original)
   return bp, rp
  end)
  if not ok then
   pcall(function() scope:close() end)
   self._preserve_ptr = nil
   return false
  end

  local button_patch_bytes = self._bytes(button_patch)
  local return_patch_bytes = self._bytes(return_patch)
  if not mem.write(button_site, button_patch_bytes) then
   pcall(function() scope:close() end)
   self._preserve_ptr = nil
   return false
  end
  if not mem.write(return_site, return_patch_bytes) then
   local current = mem.read(button_site, #button_patch_bytes)
   local restored = mem.match(current, button_original)
   if mem.match(current, button_patch_bytes) then
    restored = mem.write(button_site, button_original)
   end
   if not restored then
    self._scope = scope
    self._button_site, self._return_site = button_site, return_site
    self._button_original, self._return_original = button_original, return_original
    self._button_patch, self._return_patch = button_patch_bytes, return_patch_bytes
    self._active = true
    return false
   end
   pcall(function() scope:close() end)
   self._preserve_ptr = nil
   return false
  end

  if not mem.match(mem.read(button_site, #button_patch_bytes), button_patch_bytes)
   or not mem.match(mem.read(return_site, #return_patch_bytes), return_patch_bytes) then
   local current_return = mem.read(return_site, #return_patch_bytes)
   local current_button = mem.read(button_site, #button_patch_bytes)
   local return_restored = mem.match(current_return, return_original)
   local button_restored = mem.match(current_button, button_original)
   if mem.match(current_return, return_patch_bytes) then
    return_restored = mem.write(return_site, return_original)
   end
   if mem.match(current_button, button_patch_bytes) then
    button_restored = mem.write(button_site, button_original)
   end
   if not return_restored or not button_restored then
    self._scope = scope
    self._button_site, self._return_site = button_site, return_site
    self._button_original, self._return_original = button_original, return_original
    self._button_patch, self._return_patch = button_patch_bytes, return_patch_bytes
    self._active = true
    return false
   end
   pcall(function() scope:close() end)
   self._preserve_ptr = nil
   return false
  end

  self._scope = scope
  self._button_site = button_site
  self._return_site = return_site
  self._button_original = button_original
  self._return_original = return_original
  self._button_patch = button_patch_bytes
  self._return_patch = return_patch_bytes
  self._active = true
  return true
 end,
 set_preserve = function(self, enabled)
  if not self._preserve_ptr then return false end
  local ok = pcall(function()
   ffi.cast("uint8_t*", self._preserve_ptr)[0] = enabled and 1 or 0
  end)
  return ok
 end,
 restore = function(self)
  if not self._scope then
   self._active = false
   self._preserve_ptr = nil
   return true
  end
  local mem = Class.gamesense._mem
  local safe = true
  local button_current = mem.read(self._button_site, #self._button_patch)
  local return_current = mem.read(self._return_site, #self._return_patch)

  if mem.match(button_current, self._button_patch) then
   if not mem.write(self._button_site, self._button_original) then safe = false end
  elseif not mem.match(button_current, self._button_original) then
   safe = false
  end

  if mem.match(return_current, self._return_patch) then
   if not mem.write(self._return_site, self._return_original) then safe = false end
  elseif not mem.match(return_current, self._return_original) then
   safe = false
  end

  if not safe then
   return false
  end
  local closed = self._scope:close()
  if not closed then return false end
  self._scope = nil
  self._button_site, self._return_site = nil, nil
  self._button_original, self._return_original = nil, nil
  self._button_patch, self._return_patch = nil, nil
  self._preserve_ptr = nil
  self._active = false
  return true
 end,
 handle = function(self)
  local menu = Class.ui.menu.gamesense_settings.double_tap_return_fix
  local enabled = false
  pcall(function() enabled = menu.enabled:get() and true or false end)
  if not enabled or globals.mapname() == nil then
   self:set_preserve(false)
   self:restore()
   return
  end
  if self._active then return end
  local now = globals.realtime() or 0
  if now - self._last_attempt < 1 then return end
  self._last_attempt = now
  self:apply()
 end,
},
defensive_double_tap_on_peek = {
 _visible = {},
 _last_trigger_tick = -1000,
 _preserve_until_tick = -1,
 _last_command = -1,
 _can_hit_local = function(self, enemy, local_player)
  local ok, result = pcall(function()
   local enemy_x, enemy_y, enemy_z = entity.hitbox_position(enemy, 0)
   if enemy_x == nil or enemy_y == nil or enemy_z == nil then return false end
   local hitboxes = {0, 4, 5, 2}
   for i = 1, #hitboxes do
    local x, y, z = entity.hitbox_position(local_player, hitboxes[i])
    if x ~= nil and y ~= nil and z ~= nil then
     local trace_ok, hit, damage = pcall(client.trace_bullet, enemy, enemy_x, enemy_y, enemy_z, x, y, z, enemy)
     if trace_ok and hit == local_player and (tonumber(damage) or 0) > 0 then
      return true
     end
    end
   end
   return false
  end)
  return ok and result == true
 end,
 _double_tap_active = function(self)
  local ref = Class.util.reference.rage_double_tap
  if not ref or not ref[1] or not ref[2] then return false end
  local ok, active = pcall(function() return ui.get(ref[1]) and ui.get(ref[2]) end)
  return ok and active == true
 end,
 reset = function(self)
  self._visible = {}
  self._last_trigger_tick = -1000
  self._preserve_until_tick = -1
  self._last_command = -1
  if Class.gamesense.double_tap_return_fix then
   Class.gamesense.double_tap_return_fix:set_preserve(false)
  end
 end,
 handle = function(self, cmd)
  local menu = Class.ui.menu.gamesense_settings.defensive_double_tap_on_peek
  local enabled = false
  pcall(function() enabled = menu.enabled:get() and true or false end)
  local return_fix = Class.gamesense.double_tap_return_fix
  if not enabled or not return_fix or not return_fix._active or not cmd or globals.mapname() == nil then
   self:reset()
   return
  end

  local local_player = entity.get_local_player()
  if not local_player or not entity.is_alive(local_player) or not self:_double_tap_active() then
   self:reset()
   return
  end

  local tick = globals.tickcount() or 0
  local command_number = tonumber(cmd.command_number) or -1
  local enemies = entity.get_players(true) or {}
  if type(enemies) ~= "table" then return end
  local visible_now = {}
  local trigger = false

  for i = 1, #enemies do
   local enemy = enemies[i]
   if enemy and entity.is_alive(enemy) then
    local dormant = false
    pcall(function() dormant = entity.is_dormant(enemy) end)
    if not dormant then
     local vx, vy, vz = entity.get_prop(enemy, "m_vecVelocity")
     vx, vy, vz = tonumber(vx) or 0, tonumber(vy) or 0, tonumber(vz) or 0
     local speed = math.sqrt(vx * vx + vy * vy + vz * vz)
     local threat = speed >= 55 and self:_can_hit_local(enemy, local_player)
     if threat then
      visible_now[enemy] = true
      if not self._visible[enemy] and tick - self._last_trigger_tick >= 6 then
       trigger = true
      end
     end
    end
   end
  end

  self._visible = visible_now
  if trigger and command_number ~= self._last_command then
   self._last_command = command_number
   self._last_trigger_tick = tick
   self._preserve_until_tick = tick + 3
   pcall(function() cmd.force_defensive = true end)
  end

  return_fix:set_preserve(tick <= self._preserve_until_tick)
 end,
},
air_autostop = {
 PATCH_ADDR = 0x43372D89,
 _orig = { 0xF7, 0x40, 0x04, 0x00, 0x00, 0x02, 0x00, 0x0F, 0x84, 0x94, 0x04, 0x00, 0x00 },
 _nops = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 },
 _owns = false,
 _enabled = false,
 _write = function(self, bytes)
   return pcall(function()
     local p = ffi.cast("uint8_t*", self.PATCH_ADDR)
     for index = 1, #bytes do p[index - 1] = bytes[index] end
   end)
 end,
 _match = function(self, bytes)
   local mem = Class.gamesense._mem
   local current = mem.read(self.PATCH_ADDR, #bytes)
   return mem.match(current, bytes)
 end,
 apply = function(self)
   if self:_match(self._nops) then
     self._owns = true
     return true
   end
   if not self:_match(self._orig) then return false end
   if not self:_write(self._nops) then return false end
   self._owns = true
   return true
 end,
 restore = function(self)
   if not self._owns then return end
   if self:_match(self._nops) then
     self:_write(self._orig)
   end
   self._owns = false
 end,
 handle = function(self)
   local on = Class.ui.menu.gamesense_settings.air_autostop.enabled:get()
   if not on then
     self:restore()
     return
   end
   if globals.mapname() == nil then return end
   local local_player = entity.get_local_player()
   local scoped = local_player and entity.is_alive(local_player) and entity.get_prop(local_player, "m_bIsScoped") == 1
   if not scoped then
     self:restore()
     return
   end
   self:apply()
 end,
},
scan_accuracy_optimization = {
 _valid = nil,
 _active = {},
 _values = {},
 _retry = {},
 _seed_table = nil,
 _seed_addr = nil,
 _smoothed_fps = nil,
 _shut = false,
 _to_le32 = function(value)
   value = math.floor(value)
   if value < 0 then value = value + 0x100000000 end
   return {
    value % 0x100,
    math.floor(value / 0x100) % 0x100,
    math.floor(value / 0x10000) % 0x100,
    math.floor(value / 0x1000000) % 0x100
   }
end,
_write = function(self, addr, bytes)
  return pcall(function()
    local p = ffi.cast("uint8_t*", addr)
    for index = 1, #bytes do p[index - 1] = bytes[index] end
  end)
end,
_init_groups = function(self)
  if self._groups then return end
  local function join(a, b)
    local t = {}
    for index = 1, #a do t[#t + 1] = a[index] end
    for index = 1, #b do t[#t + 1] = b[index] end
    return t
  end
  local le = self._to_le32
  self._groups = {
   sample = {
    { kind = "cmp_imm32", address = 0x4333278D, register = 0xFF, original = join({ 0x81, 0xFF }, le(0x80)), build = function(v) return join({ 0x81, 0xFF }, le(v)) end },
    { kind = "cmp_imm32", address = 0x4333285D, register = 0xF9, original = join({ 0x81, 0xF9 }, le(0x80)), build = function(v) return join({ 0x81, 0xF9 }, le(v)) end },
   },
  seed = {
   { kind = "disp32", address = 0x433326CF, prefix = { 0x0F, 0xB6, 0x88 }, original = join({ 0x0F, 0xB6, 0x88 }, le(0x4346FC50)), build = function(v) return join({ 0x0F, 0xB6, 0x88 }, le(v)) end },
   { kind = "disp32", address = 0x4333273E, prefix = { 0x0F, 0xB6, 0x87 }, original = join({ 0x0F, 0xB6, 0x87 }, le(0x4346FC50)), build = function(v) return join({ 0x0F, 0xB6, 0x87 }, le(v)) end },
   { kind = "disp32", address = 0x433327B3, prefix = { 0x0F, 0xB6, 0x91 }, original = join({ 0x0F, 0xB6, 0x91 }, le(0x4346FC50)), build = function(v) return join({ 0x0F, 0xB6, 0x91 }, le(v)) end },
   { kind = "disp32", address = 0x4333281F, prefix = { 0x0F, 0xB6, 0x80 }, original = join({ 0x0F, 0xB6, 0x80 }, le(0x4346FC50)), build = function(v) return join({ 0x0F, 0xB6, 0x80 }, le(v)) end },
  },
  percent_cap = {
   { kind = "push_imm8", address = 0x43332890, original = { 0x6A, 0x64 }, build = function(v) return { 0x6A, math.floor(v) % 0x100 } end },
  },
  hitbox_cap = {
   { kind = "push_imm8", address = 0x433337EA, original = { 0x6A, 0x13 }, build = function(v) return { 0x6A, math.floor(v) % 0x100 } end },
   { kind = "push_imm8", address = 0x43333C88, original = { 0x6A, 0x13 }, build = function(v) return { 0x6A, math.floor(v) % 0x100 } end },
  },
  hitbox_mask = {
   { kind = "mov_esi_imm32", address = 0x43333349, original = join({ 0xBE }, le(0xCA)), build = function(v) return join({ 0xBE }, le(v)) end },
  },
  distance_bypass = {
   { kind = "bytes", address = 0x43333078, original = { 0x76, 0x27 }, patched = { 0xEB, 0x27 } },
   { kind = "bytes", address = 0x433330A8, original = { 0x76, 0x0D }, patched = { 0xEB, 0x0D } },
  },
  }
  pcall(function()
    self._seed_table = ffi.new("unsigned char[512]")
    for index = 0, 511 do self._seed_table[index] = index % 256 end
    self._seed_addr = tonumber(ffi.cast("uintptr_t", ffi.cast("void*", self._seed_table)))
  end)
end,
_patch_valid = function(self, patch)
  local mem = Class.gamesense._mem
  local current = mem.read(patch.address, #patch.original)
  if mem.match(current, patch.original) then return true end
  if patch.kind == "bytes" and mem.match(current, patch.patched) then return true end
  if not current then return false end
  if patch.kind == "cmp_imm32" then return current[1] == 0x81 and current[2] == patch.register end
  if patch.kind == "push_imm8" then return current[1] == 0x6A end
  if patch.kind == "mov_esi_imm32" then return current[1] == 0xBE end
  if patch.prefix then
    for index = 1, #patch.prefix do
      if current[index] ~= patch.prefix[index] then return false end
    end
    return true
  end
  return false
end,
_check_valid = function(self)
  self:_init_groups()
  self._valid = self._seed_addr ~= nil
  return self._valid
end,
_apply_group = function(self, group, value)
  local applied = 0
  local total = #group
  local mem = Class.gamesense._mem
  for index = 1, total do
    local patch = group[index]
    if self:_patch_valid(patch) then
      local patched = patch.kind == "bytes" and patch.patched or patch.build(value)
      local current = mem.read(patch.address, #patched)
      if mem.match(current, patched) or self:_write(patch.address, patched) then
        applied = applied + 1
      end
    end
  end
  return applied, total
end,
_restore_group = function(self, name)
  if not self._active[name] then return end
  local group = self._groups[name]
  local expected = self._values[name]
  local mem = Class.gamesense._mem
  for index = 1, #group do
    local patch = group[index]
    local current = mem.read(patch.address, #patch.original)
    if mem.match(current, patch.original) then
    elseif patch.kind == "bytes" then
      if mem.match(current, patch.patched) then self:_write(patch.address, patch.original) end
    elseif expected ~= nil then
      local success, wanted = pcall(patch.build, expected)
      if success and mem.match(current, wanted) then self:_write(patch.address, patch.original) end
    end
  end
  self._active[name] = false
  self._values[name] = nil
  self._retry[name] = nil
end,
_update_group = function(self, name, enabled, value)
  if not enabled then
    self:_restore_group(name)
    return
  end
  if self._active[name] and self._values[name] == value and not self._retry[name] then return end
  local applied, total = self:_apply_group(self._groups[name], value)
  if applied > 0 then
    self._active[name] = true
    self._values[name] = value
  end
  self._retry[name] = applied < total
end,
restore = function(self)
  if not self._groups then return end
  for name in pairs(self._groups) do
    self:_restore_group(name)
  end
  self._retry = {}
end,
_is_fakeduck = function(self)
  local success, active = false, false
  pcall(function()
    local fake_duck_ref = Class.util.reference.rage_fake_duck
    if fake_duck_ref and fake_duck_ref[1] then active = ui.get(fake_duck_ref[1]) and true or false end
  end)
  return active
end,
_is_onground = function(self)
  local local_player = entity.get_local_player()
  if not local_player then return true end
  local player_flags = entity.get_prop(local_player, "m_fFlags") or 0
  return bit.band(player_flags, 1) ~= 0
end,
_get_sample_count = function(self)
  if self:_is_fakeduck() then return 128 end
  if self._smoothed_fps and self._smoothed_fps < 128 then return 128 end
  return 256
end,
update = function(self)
  if self._shut then return end
  if not self:_check_valid() then return end
  local on = Class.ui.menu.gamesense_settings.scan_accuracy_optimization.enabled:get()
  if not on then
    self:restore()
    return
  end
  local samples = self:_get_sample_count()
  self:_update_group("seed", true, self._seed_addr)
  self:_update_group("sample", true, samples)
  local velocity_percent = 76
  if globals.mapname() ~= nil and not self:_is_onground() then
    velocity_percent = 65
  end
  self:_update_group("percent_cap", true, velocity_percent)
  self:_update_group("hitbox_cap", true, 18)
  self:_update_group("hitbox_mask", true, 255)
  self:_update_group("distance_bypass", true, true)
end,
handle = function(self)
  if self._shut then return end
  local frame_time = globals.frametime()
  if frame_time and frame_time > 0 then
    local instant_rate = 1 / frame_time
    if instant_rate > 1000 then instant_rate = 1000 end
    self._smoothed_fps = self._smoothed_fps == nil and instant_rate or (self._smoothed_fps * 0.9 + instant_rate * 0.1)
  end
  if globals.mapname() == nil then return end
  self:update()
end,
},
spread_autostop_fix = {
  _sites = nil,
  _active = false,
  _last_scan = -10,
  _find = function(self)
    if self._sites ~= nil and #self._sites > 0 then return self._sites end
    local now = globals.realtime() or 0
    if now - (self._last_scan or -10) < 1 then return self._sites or {} end
    self._last_scan = now
    self._sites = {}

    local function add(addr, orig, write)
      if not addr or addr == 0 then return end
      self._sites[#self._sites + 1] = { addr = addr, orig = orig, write = write }
    end

    local function match_at(addr, orig)
      local ok, matched = pcall(function()
        local p = ffi.cast("uint8_t*", addr)
        for i = 1, #orig do
          if p[i - 1] ~= orig[i] then return false end
        end
        return true
      end)
      return ok and matched
    end

    -- Absolute patches (same family as air_autostop / scan_accuracy_optimization on this crack family)
    -- 1) HC samples 128 -> 256
    local abs = {
      {
        addr = 0x4333278D,
        orig = {0x81, 0xFF, 0x80, 0x00, 0x00, 0x00},
        write = {0x81, 0xFF, 0x00, 0x01, 0x00, 0x00},
      },
      {
        addr = 0x4333285D,
        orig = {0x81, 0xF9, 0x80, 0x00, 0x00, 0x00},
        write = {0x81, 0xF9, 0x00, 0x01, 0x00, 0x00},
      },
      -- velocity percent cap 100 -> 70 (stricter accuracy for stop check inside HC)
      {
        addr = 0x43332890,
        orig = {0x6A, 0x64},
        write = {0x6A, 0x46},
      },
      -- autostop ground gate: test [eax+4], 0x20000 / je -> NOP (same site air_autostop uses, always on)
      {
        addr = 0x43372D89,
        orig = {0xF7, 0x40, 0x04, 0x00, 0x00, 0x02, 0x00, 0x0F, 0x84, 0x94, 0x04, 0x00, 0x00},
        write = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
      },
    }
    for i = 1, #abs do
      local a = abs[i]
      if match_at(a.addr, a.orig) then
        add(a.addr, a.orig, a.write)
      end
    end

    -- client.dll signature samples
    local sigs = {
      { "client.dll", "\\x81\\xFF\\x80\\x00\\x00\\x00", {0x81, 0xFF, 0x80, 0x00, 0x00, 0x00}, {0x81, 0xFF, 0x00, 0x01, 0x00, 0x00} },
      { "client.dll", "\\x81\\xF9\\x80\\x00\\x00\\x00", {0x81, 0xF9, 0x80, 0x00, 0x00, 0x00}, {0x81, 0xF9, 0x00, 0x01, 0x00, 0x00} },
    }
    for i = 1, #sigs do
      local mod, pat, orig, write = sigs[i][1], sigs[i][2], sigs[i][3], sigs[i][4]
      local ok, addr = pcall(function()
        return client.find_signature(mod, pat)
      end)
      if ok and addr and addr ~= 0 then
        local a = tonumber(addr) or addr
        if match_at(a, orig) then
          add(a, orig, write)
        end
      end
    end

    -- skeet.dll by fixed size: sample cmps
    pcall(function()
      if not pcall(ffi.typeof, "GOTH_SF_ME*") then
        ffi.cdef[[
          typedef void* GOTH_SF_HANDLE;
          typedef unsigned long GOTH_SF_DWORD;
          typedef struct {
            GOTH_SF_DWORD dwSize;
            GOTH_SF_DWORD th32ModuleID;
            GOTH_SF_DWORD th32ProcessID;
            GOTH_SF_DWORD GlblcntUsage;
            GOTH_SF_DWORD ProccntUsage;
            unsigned char* modBaseAddr;
            GOTH_SF_DWORD modBaseSize;
            GOTH_SF_HANDLE hModule;
            char szModule[256];
            char szExePath[260];
          } GOTH_SF_ME;
          GOTH_SF_HANDLE __stdcall CreateToolhelp32Snapshot(GOTH_SF_DWORD, GOTH_SF_DWORD);
          int __stdcall Module32First(GOTH_SF_HANDLE, GOTH_SF_ME*);
          int __stdcall Module32Next(GOTH_SF_HANDLE, GOTH_SF_ME*);
          int __stdcall CloseHandle(GOTH_SF_HANDLE);
        ]]
      end
      local kernel = ffi.load("kernel32")
      local snap = kernel.CreateToolhelp32Snapshot(bit.bor(0x8, 0x10), 0)
      if snap ~= nil and snap ~= ffi.cast("GOTH_SF_HANDLE", -1) then
        local entry = ffi.new("GOTH_SF_ME")
        entry.dwSize = ffi.sizeof("GOTH_SF_ME")
        if kernel.Module32First(snap, entry) ~= 0 then
          repeat
            if tonumber(entry.modBaseSize) == 13944320 then
              local base = entry.modBaseAddr
              local p = ffi.cast("uint8_t*", base)
              local needles = {
                { {0x81, 0xFF, 0x80, 0x00, 0x00, 0x00}, {0x81, 0xFF, 0x00, 0x01, 0x00, 0x00} },
                { {0x81, 0xF9, 0x80, 0x00, 0x00, 0x00}, {0x81, 0xF9, 0x00, 0x01, 0x00, 0x00} },
              }
              for ti = 1, #needles do
                local needle, write = needles[ti][1], needles[ti][2]
                for off = 0, 0x1C0000 do
                  local ok = true
                  for j = 1, #needle do
                    if p[off + j - 1] ~= needle[j] then ok = false break end
                  end
                  if ok then
                    add(tonumber(ffi.cast("uintptr_t", base + off)), needle, write)
                    break
                  end
                end
              end
              break
            end
          until kernel.Module32Next(snap, entry) == 0
        end
        kernel.CloseHandle(snap)
      end
    end)

    return self._sites
  end,
  _write = function(self, addr, bytes)
    return pcall(function()
      local kernel = ffi.load("kernel32")
      local ptr = ffi.cast("uint8_t*", addr)
      local old = ffi.new("unsigned long[1]")
      kernel.VirtualProtect(ptr, #bytes, 0x40, old)
      for i = 1, #bytes do ptr[i - 1] = bytes[i] end
      kernel.VirtualProtect(ptr, #bytes, old[0], old)
    end)
  end,
  apply = function(self)
    local sites = self:_find()
    if #sites == 0 then return false end
    for i = 1, #sites do
      local s = sites[i]
      self:_write(s.addr, s.write)
    end
    self._active = true
    return true
  end,
  restore = function(self)
    if not self._active or not self._sites then
      self._active = false
      return
    end
    for i = 1, #self._sites do
      local s = self._sites[i]
      if s.orig then self:_write(s.addr, s.orig) end
    end
    self._active = false
  end,
  handle = function(self)
    local on = false
    pcall(function()
      on = Class.ui.menu.gamesense_settings.spread_autostop_fix.enabled:get() and true or false
    end)
    if not on then
      self:restore()
      return
    end
    if globals.mapname() == nil then return end
    if not self._active then
      self:apply()
    end
  end,
},
backtrack_record_fix = {
  MAX_MOVE = 512,
  _distance = nil,
  _distance_addr = nil,
  _patches = nil,
  _lr_dynamic = nil,
  _applied = {},
  _failed = nil,
  _owned = {},
  _init = function(self)
    if self._patches then return true end
    pcall(function()
      self._distance = ffi.new("float[1]", self.MAX_MOVE * self.MAX_MOVE)
      self._distance_addr = tonumber(ffi.cast("uintptr_t", self._distance))
    end)
    if not self._distance_addr then return false end

    local function le32(v)
      v = math.floor(v)
      if v < 0 then v = v + 0x100000000 end
      return {
        v % 0x100,
        math.floor(v / 0x100) % 0x100,
        math.floor(v / 0x10000) % 0x100,
        math.floor(v / 0x1000000) % 0x100,
      }
    end
    local function join(a, b)
      local t = {}
      for i = 1, #a do t[#t + 1] = a[i] end
      for i = 1, #b do t[#t + 1] = b[i] end
      return t
    end

    local dist_orig = join({0x0F, 0x2F, 0x15}, le32(0x43472B60))
    local dist_patch = join({0x0F, 0x2F, 0x15}, le32(self._distance_addr))

    self._patches = {
      core = {
        {
          id = "distance",
          address = 0x433AED50,
          original = dist_orig,
          patched = dist_patch,
        },
        {
          id = "gap_default",
          address = 0x433AF012,
          original = {0x83, 0xF9, 0x08},
          patched = {0x83, 0xF9, 0x14},
        },
      },
      lag_record = {
        {
          id = "lr_lim_a",
          address = 0x433AEE6C,
          original = {0x3D, 0x80, 0x00, 0x00, 0x00},
          patched = {0x3D, 0x80, 0x00, 0x00, 0x00},
        },
        {
          id = "lr_lim_b",
          address = 0x433F94FD,
          original = {0x3D, 0x80, 0x00, 0x00, 0x00},
          patched = {0x3D, 0x80, 0x00, 0x00, 0x00},
        },
        {
          id = "lr_ja",
          address = 0x433259A4,
          original = {0x0F, 0x87, 0x2E, 0x04, 0x00, 0x00},
          patched = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
        },
      },
    }
    self._lr_dynamic = {
      { address = 0x433AF091, original = {0x83, 0xF8, 0x0A} },
      { address = 0x433AF167, original = {0x83, 0xF8, 0x0A} },
      { address = 0x433F9645, original = {0x83, 0xF8, 0x0A} },
      { address = 0x433F96F3, original = {0x83, 0xF8, 0x0A} },
    }
    return true
  end,
  -- Known-build descriptors above are never accepted on opcode-prefix matches.
  -- The lagrecords reference reads/validates records; it does not validate these patch addresses.
  _memory_api = function(self)
    if self._api then return self._api end
    if not ffi.abi("win") or not ffi.abi("32bit") then return nil end
    local ok, api = pcall(function()
      pcall(ffi.cdef, [[
        typedef struct {
          void* base; void* allocation_base; uint32_t allocation_protect;
          uintptr_t region_size; uint32_t state; uint32_t protect; uint32_t kind;
        } afterglow_record_mbi_v1;
      ]])
      local memory = require("lib/memory")
      return {
        query = memory.bind("kernel32.dll", "VirtualQuery", "uintptr_t", {"uintptr_t", "void*", "uintptr_t"}),
        protect = memory.bind("kernel32.dll", "VirtualProtect", "int", {"uintptr_t", "uintptr_t", "uint32_t", "uint32_t*"}),
        flush = memory.bind("kernel32.dll", "FlushInstructionCache", "int", {"uintptr_t", "uintptr_t", "uintptr_t"}),
        process = memory.bind("kernel32.dll", "GetCurrentProcess", "uintptr_t", {}),
      }
    end)
    if not ok then return nil end
    self._api = api
    return api
  end,
  _readable = function(self, address, length)
    local api = self:_memory_api()
    if not api or not address or address < 0x10000 or length < 1 then return false end
    local cursor, finish = address, address + length
    while cursor < finish do
      local info = ffi.new("afterglow_record_mbi_v1[1]")
      if tonumber(api.query(cursor, info, ffi.sizeof(info))) ~= ffi.sizeof(info) then return false end
      local region_end = tonumber(ffi.cast("uintptr_t", info[0].base)) + tonumber(info[0].region_size)
      local protection = tonumber(info[0].protect)
      local access = bit.band(protection, 0xFF)
      if info[0].state ~= 0x1000 or bit.band(protection, 0x100) ~= 0
        or (access ~= 0x02 and access ~= 0x04 and access ~= 0x08 and access ~= 0x20 and access ~= 0x40 and access ~= 0x80)
        or region_end <= cursor then return false end
      cursor = math.min(region_end, finish)
    end
    return true
  end,
  _read = function(self, address, length)
    if not self:_readable(address, length) then return nil end
    local bytes, pointer = {}, ffi.cast("const uint8_t*", address)
    for i = 1, length do bytes[i] = pointer[i - 1] end
    return bytes
  end,
  _write = function(self, address, bytes)
    if not self:_readable(address, #bytes) then return false end
    local api, old = self:_memory_api(), ffi.new("uint32_t[1]")
    if tonumber(api.protect(address, #bytes, 0x40, old)) == 0 then return false end
    local buffer = ffi.new("uint8_t[?]", #bytes, bytes)
    ffi.copy(ffi.cast("void*", address), buffer, #bytes)
    local restored = tonumber(api.protect(address, #bytes, old[0], old)) ~= 0
    local flushed = tonumber(api.flush(api.process(), address, #bytes)) ~= 0
    return restored and flushed and self:_match(self:_read(address, #bytes), bytes)
  end,
  _match = function(self, a, b)
    if not a or not b or #a ~= #b then return false end
    for i = 1, #a do if a[i] ~= b[i] then return false end end
    return true
  end,
  restore = function(self)
    local clean = true
    for address, owned in pairs(self._owned) do
      local current = self:_read(address, #owned.original)
      if self:_match(current, owned.original) then
        self._owned[address] = nil
      elseif self:_match(current, owned.patched) then
        if self:_write(address, owned.original) then self._owned[address] = nil
        else clean = false end
      else
        -- Another script changed the site. Never overwrite its bytes.
        self._owned[address] = nil
        clean = false
      end
    end
    return clean
  end,
  _sync = function(self, plan)
    local wanted = {}
    -- Validate the entire requested patch set before changing a single byte.
    for _, patch in ipairs(plan) do
      if wanted[patch.address] then return false, "duplicate patch address" end
      wanted[patch.address] = patch
      local owned = self._owned[patch.address]
      local expected = owned and owned.patched or patch.original
      if not self:_match(self:_read(patch.address, #expected), expected) then
        return false, "unsupported or externally modified site at " .. string.format("0x%X", patch.address)
      end
    end
    for address, owned in pairs(self._owned) do
      if not self:_match(self:_read(address, #owned.patched), owned.patched) then
        return false, "owned site changed at " .. string.format("0x%X", address)
      end
    end
    -- Restore removed options first, checking ownership on every write.
    for address, owned in pairs(self._owned) do
      if not wanted[address] then
        if not self:_write(address, owned.original) then self:restore(); return false, "restore failed" end
        self._owned[address] = nil
      end
    end
    for _, patch in ipairs(plan) do
      local owned = self._owned[patch.address]
      local current = owned and owned.patched or patch.original
      if not self:_match(current, patch.patched) then
        -- Journal before writing, so a failed readback can still be rolled back.
        self._owned[patch.address] = {original = owned and owned.original or patch.original, patched = patch.patched}
        if not self:_write(patch.address, patch.patched) then
          -- A refused write may have left the previous owned bytes intact.
          local observed = self:_read(patch.address, #current)
          if self:_match(observed, current) then self._owned[patch.address] = owned end
          self:restore()
          return false, "patch write/verification failed"
        end
      end
    end
    return true
  end,
  _plan = function(self, lag_records, gap)
    local plan = {}
    for _, patch in ipairs(self._patches.core) do plan[#plan + 1] = patch end
    if lag_records then
      for _, patch in ipairs(self._patches.lag_record) do plan[#plan + 1] = patch end
      for _, patch in ipairs(self._lr_dynamic) do
        plan[#plan + 1] = {address = patch.address, original = patch.original, patched = {0x83, 0xF8, gap}}
      end
    end
    return plan
  end,
  handle = function(self)
    local menu = Class.ui.menu.gamesense_settings.backtrack_record_fix
    if not menu or not menu.enabled:get() or globals.mapname() == nil then
      if next(self._owned) then self:restore() end
      self._failed = nil
      return
    end
    if self._failed then return end
    if not self:_init() then self._failed = "initialization failed"
    else
      local extended = menu.extended_lag_records:get()
      local gap = tonumber((extended and menu.extended_record_gap or menu.record_gap):get()) or 3
      gap = math.max(1, math.min(extended and 20 or 10, math.floor(gap)))
      local ok, reason = self:_sync(self:_plan(menu.lag_records:get(), gap))
      if not ok then self._failed = reason or "patch validation failed" end
    end
    if self._failed then
      self:restore()
      pcall(client.error_log, "[afterglow] Backtrack Record Fix disabled: " .. self._failed)
      -- A rejected build must not appear to have a working fix enabled.
      menu.enabled:set(false)
    end
  end,
},
custom_quick_switch = {
 _active = false,
 _restore = function(self)
   local reference = Class.util.reference.misc_quick_switch
   if not reference then return end
   pcall(function()
     ui.set_enabled(reference, true)
   end)
 end,
 _disable_gs = function(self)
   local reference = Class.util.reference.misc_quick_switch
   if not reference then return end
   pcall(function()
     ui.set(reference, false)
     ui.set_enabled(reference, false)
   end)
 end,
 setup = function(self)
   local menu_item = Class.ui.menu.gamesense_settings.custom_quick_switch
   if not menu_item then return end
   local function apply()
     local on = menu_item.enabled:get()
     self._active = on
     if on then
       self:_disable_gs()
     else
     self:_restore()
   end
 end
 menu_item.enabled:set_callback(apply)
 apply()
 end,
 tick = function(self)
   if not self._active then return end
   self:_disable_gs()
 end,
 on_grenade_thrown = function(self, e)
   if not self._active then return end
   local local_player = entity.get_local_player()
   if not local_player then return end
   local uid = e and e.userid
   if not uid then return end
   if client.userid_to_entindex(uid) ~= local_player then return end
   client.delay_call(globals.tickinterval(), client.exec, "slot3; slot2; slot1")
 end,
 on_weapon_fire = function(self, e)
   if not self._active then return end
   local local_player = entity.get_local_player()
   if not local_player then return end
   if not e or e.weapon ~= "weapon_taser" then return end
   if cvar.sv_infinite_ammo and cvar.sv_infinite_ammo:get_int() == 1 then return end
   local uid = e.userid
   if not uid then return end
   if client.userid_to_entindex(uid) ~= local_player then return end
   client.exec("slot3; slot2; slot1")
 end,
 shutdown = function(self)
   self:_restore()
   self._active = false
 end
},


}
local function addon_enabled(name)
  local misc = Class.ui.menu.misc_tab
  if not misc then return false end

  if name == "Enemy Chat Viewer" then
    local reference = misc.event_logger
      and misc.event_logger.force_teammate_aimbot
      and misc.event_logger.force_teammate_aimbot.enemy_chat_viewer
    return reference and reference:get() and true or false
  end

  if name == "Console Filter" or name == "Clean On Level Init" or name == "Clean On New Round" then
    local console = misc.console_enhancement
    local mode = console and console.mode
    if not mode then return false end
    local selected = mode:get()
    return selected == name
  end

  local addons = misc.addons
  return addons and addons:get(name) and true or false
end
Class.misc.unlock_hidden_cvars = {
 _interface = nil,
 _iterator = nil,
 _saved = {},
 _active = false,
 _last_attempt = -2,
 _last_count = 0,
 _last_error = nil,
 _init = function(self)
  if self._iterator ~= nil then return true end
  local now = globals.realtime() or 0
  if now - self._last_attempt < 2 then return false end
  self._last_attempt = now
  local ok, result = pcall(function()
   if not pcall(ffi.typeof, "GOTH_CVAR_FACTORY_ITERATOR") then
    ffi.cdef[[
     typedef void* (__thiscall* GOTH_CVAR_FACTORY_ITERATOR)(void*);
     typedef void (__thiscall* GOTH_CVAR_ITER_SET_FIRST)(void*);
     typedef unsigned char (__thiscall* GOTH_CVAR_ITER_IS_VALID)(void*);
     typedef void (__thiscall* GOTH_CVAR_ITER_NEXT)(void*);
     typedef void* (__thiscall* GOTH_CVAR_ITER_GET)(void*);
    ]]
   end
   local interface = client.create_interface("vstdlib.dll", "VEngineCvar007")
   if interface == nil then error("ICvar interface unavailable") end
   local vtable = ffi.cast("void***", interface)[0]
   if vtable == nil or vtable[42] == nil then error("ICvar iterator entry unavailable") end
   local factory = ffi.cast("GOTH_CVAR_FACTORY_ITERATOR", vtable[42])
   local iterator = factory(interface)
   if iterator == nil then error("ICvar iterator creation failed") end
   self._interface = interface
   self._iterator = iterator
   return true
  end)
  if not ok then
   self._last_error = tostring(result)
   return false
  end
  self._last_error = nil
  return result == true
 end,
 _walk = function(self, callback)
  if not self._iterator then return false end
  local vtable = ffi.cast("void***", self._iterator)[0]
  if vtable == nil then return false end
  local set_first = ffi.cast("GOTH_CVAR_ITER_SET_FIRST", vtable[0])
  local is_valid = ffi.cast("GOTH_CVAR_ITER_IS_VALID", vtable[2])
  local next_item = ffi.cast("GOTH_CVAR_ITER_NEXT", vtable[1])
  local get_item = ffi.cast("GOTH_CVAR_ITER_GET", vtable[3])
  if set_first == nil or is_valid == nil or next_item == nil or get_item == nil then return false end
  set_first(self._iterator)
  local walked = 0
  while is_valid(self._iterator) ~= 0 and walked < 20000 do
   local item = get_item(self._iterator)
   if item ~= nil then callback(item) end
   next_item(self._iterator)
   walked = walked + 1
  end
  return true
 end,
 apply = function(self)
  if self._active then return end
  if not self:_init() then return end
  local saved = {}
  local changed = 0
  local ok = pcall(function()
   local walked = self:_walk(function(item)
    local flags_ptr = ffi.cast("int32_t*", ffi.cast("uint8_t*", item) + 0x14)
    local flags = tonumber(flags_ptr[0])
    if flags ~= nil and bit.band(flags, 0x12) ~= 0 then
     saved[#saved + 1] = { ptr = flags_ptr, value = bit.band(flags, 0x12) }
     flags_ptr[0] = bit.band(flags, bit.bnot(0x12))
     changed = changed + 1
    end
   end)
   if not walked then error("ICvar enumeration failed") end
  end)
  if not ok then
   for index = #saved, 1, -1 do
    pcall(function()
     local current = tonumber(saved[index].ptr[0]) or 0
     saved[index].ptr[0] = bit.bor(bit.band(current, bit.bnot(0x12)), saved[index].value)
    end)
   end
   self._saved = {}
   self._active = false
   self._last_error = "Cvar flags could not be updated"
   return
  end
  self._saved = saved
  self._last_count = changed
  self._active = true
  self._last_error = nil
 end,
 restore = function(self)
  for index = #self._saved, 1, -1 do
   local item = self._saved[index]
   pcall(function()
    local current = tonumber(item.ptr[0]) or 0
    item.ptr[0] = bit.bor(bit.band(current, bit.bnot(0x12)), item.value)
   end)
  end
  self._saved = {}
  self._active = false
 end,
 sync = function(self)
  if addon_enabled("Unlock Hidden Cvars") then
   self:apply()
  elseif self._active or #self._saved > 0 then
   self:restore()
  end
 end,
 shutdown = function(self)
  self:restore()
 end
}
Class.misc.duck_peek_assist_fix = {
 altered = false,
 saved = nil,
 _modes = {
  [0] = "Always on",
  [1] = "On hotkey",
  [2] = "Toggle",
  [3] = "Off hotkey",
 },
on_setup_command = function(self, cmd)
  if not addon_enabled("Allow Duck on FD") then
    if self.altered and self.saved ~= nil then
      local refs = Class.util.reference.rage_fake_duck
      local hotkey = refs and (refs[2] or refs[1])
      if hotkey then
        local restore = self.saved
        if type(restore) == "number" then
          restore = self._modes[restore] or restore
        end
        pcall(ui.set, hotkey, restore)
      end
      self.altered = false
      self.saved = nil
    end
    return
  end
  local local_player = entity.get_local_player()
  if not local_player or not entity.is_alive(local_player) then return end
  local refs = Class.util.reference.rage_fake_duck
  if not refs then return end
  local checkbox, hotkey = refs[1], refs[2] or refs[1]
  if not hotkey then return end
  local duck_amt = entity.get_prop(local_player, "m_flDuckAmount") or 0
  local duck_active = (cmd.in_duck == 1) and duck_amt > 0.8
  local active = false
  pcall(function()
    if checkbox then active = ui.get(checkbox) and true or false end
    if not active and hotkey then
      local v = ui.get(hotkey)
      if v == true or v == 1 then active = true end
    end
  end)
  if duck_active and active and not self.altered then
    local mode_val = nil
    pcall(function()
      local a, b, c = ui.get(hotkey)
      mode_val = b or c or a
    end)
    self.saved = mode_val
    local target = "Off hotkey"
    if mode_val == 2 or mode_val == 3 or mode_val == "Toggle" or mode_val == "Off hotkey" then
      target = "On hotkey"
    end
    pcall(ui.set, hotkey, target)
    self.altered = true
  elseif (not duck_active) and self.altered then
    if self.saved ~= nil then
      local restore = self.saved
      if type(restore) == "number" then
        restore = self._modes[restore] or restore
      end
      pcall(ui.set, hotkey, restore)
    end
    self.saved = nil
    self.altered = false
  end
end,
}

Class.antiaim.anti_bruteforce = {
 stage = 0,
 tick = 0,
 offset = 0,
 time = -1,
 target = nil,
 clear = function(self)
   self.stage = 0
   self.tick = 0
   self.offset = 0
   self.time = -1
   self.target = nil
 end,
 _enabled = function(self)
   local menu = Class.ui.menu.antiaim_tab.additional.fakelag.anti_bruteforce
   return menu and menu.enabled and menu.enabled:get()
 end,
 _condition_allowed = function(self)
   local menu = Class.ui.menu.antiaim_tab.additional.fakelag.anti_bruteforce
   if not menu or not menu.conditions then
     return false
   end

   -- Anti-Bruteforce must have at least one explicitly selected condition.
   -- An empty multiselect is a hard disable, never an implicit "all states".
   local selected = nil
   local selected_ok = pcall(function()
     selected = menu.conditions:get()
   end)
   if not selected_ok or type(selected) ~= "table" or next(selected) == nil then
     return false
   end

   local local_player = entity.get_local_player()
   if not local_player or not entity.is_alive(local_player) then
     return false
   end

   local flags = tonumber(entity.get_prop(local_player, "m_fFlags")) or 0
   local vx = tonumber(entity.get_prop(local_player, "m_vecVelocity[0]")) or 0
   local vy = tonumber(entity.get_prop(local_player, "m_vecVelocity[1]")) or 0
   local speed = math.sqrt(vx * vx + vy * vy)
   local duck = tonumber(entity.get_prop(local_player, "m_flDuckAmount")) or 0
   local fake_duck = false
   pcall(function()
     local ref = Class.util.reference.rage_fake_duck
     fake_duck = ref and ref[1] and ui.get(ref[1]) or false
   end)
   local is_ducking = duck > 0.7 or fake_duck == true
   local on_ground = bit.band(flags, 1) ~= 0

   -- Freestanding is an AA overlay, not a movement state. Keep evaluating the
   -- player's actual movement condition while Freestanding is active.
   local state
   if not on_ground then
     state = is_ducking and "Air Crouch" or "Air"
   elseif is_ducking then
     state = speed > 10 and "Sneaking" or "Crouch"
   else
     local slow_walk = false
     pcall(function()
       local ref = Class.util.reference.aa_slow_walk
       slow_walk = ref and ref[1] and ref[2] and ui.get(ref[1]) and ui.get(ref[2]) or false
     end)
     if slow_walk and speed > 10 then
       state = "Slowing"
     elseif speed > 5 then
       state = "Running"
     else
       state = "Standing"
     end
   end

   local selected_state = state == "Air Crouch" and "Air Crouching"
     or state == "Crouch" and "Crouching"
     or state
   for _, condition in pairs(selected) do
     if condition == selected_state or condition == "Shared" then
       return true
     end
   end

   return false
 end,
 _set_timeout = function(self, menu)
   local timeout = tonumber(menu.timeout:get()) or 3
   if timeout <= 0 then
     self.time = -2
   else
   self.time = globals.realtime() + timeout
 end
 end,
 _pick_offset = function(self, menu)
   -- gasolina: Increasing rand 5..15 / Decreasing -15..5 / Meta stage*2 * inverter
   local mode = menu.mode:get()
   if mode == "Increasing" then
     return math.random(5, 15)
   elseif mode == "Decreasing" then
     return math.random(-15, 5)
   end
   local inverted = false
   pcall(function()
     inverted = Class.util.antiaim.lr_inverted and true or false
   end)
   if not inverted then
     pcall(function()
       local cs = Class.util.antiaim.current_settings
       inverted = false
     end)
   end
   return self.stage * 2 * (inverted and 1 or -1)
 end,
 _eye = function(self, player)
   local origin_x, origin_y, origin_z = entity.get_prop(player, "m_vecOrigin")
   if not origin_x then
     return nil
   end
   local offset_x, offset_y, offset_z = entity.get_prop(player, "m_vecViewOffset")
   if offset_x then
     return origin_x + offset_x, origin_y + offset_y, origin_z + offset_z
   end
   return origin_x, origin_y, origin_z + (entity.get_prop(player, "m_vecViewOffset[2]") or 64)
 end,
 _segment_distance = function(self, ax, ay, az, bx, by, bz, px, py, pz)
   local dx, dy, dz = bx - ax, by - ay, bz - az
   local length_squared = dx * dx + dy * dy + dz * dz
   local factor = 0
   if length_squared > 1e-6 then
     factor = ((px - ax) * dx + (py - ay) * dy + (pz - az) * dz) / length_squared
     factor = math.max(0, math.min(1, factor))
   end
   local closest_x = ax + dx * factor
   local closest_y = ay + dy * factor
   local closest_z = az + dz * factor
   local distance_x = closest_x - px
   local distance_y = closest_y - py
   local distance_z = closest_z - pz
   return math.sqrt(distance_x * distance_x + distance_y * distance_y + distance_z * distance_z)
 end,
 _notify = function(self, shooter, distance)
   local name = entity.get_player_name(shooter) or "unknown"
   local base = Class.util.accent_color.first or {255, 255, 255, 255}
   local accent = {base[1] or 255, base[2] or 255, base[3] or 255, base[4] or 255}
   local offset = tonumber(self.offset) or 0
   local offset_str = (offset > 0 and ("+" .. offset) or tostring(offset)) .. "°"
   -- Bullet distance to the local player replaces the stage in every display.
   local dist_str = string.format("%du", math.floor((tonumber(distance) or 0) + 0.5))
   if Class.misc.notifications_ui and Class.misc.notifications_ui:should_show("Anti-Bruteforce") then
     Class.render.notifications:push(
       string.format("/rAnti-Bruteforce updated by /v%s/r's shot", name),
       "antibrute"
     )
   end
   if self._event_logger_enabled and self:_event_logger_enabled() then
     local white = {240, 240, 240}
     Class.misc.event_logger:_emit(accent, white, {
       {text = "Anti-Bruteforce updated by ", color = white},
       {text = tostring(name), color = accent},
       {text = "'s shot", color = white},
       {text = " (", color = white},
       {text = dist_str, color = accent},
       {text = " · ", color = white},
       {text = offset_str, color = accent},
       {text = ")", color = white},
       {text = " (stage=", color = white},
       {text = tostring(self.stage), color = accent},
       {text = ")", color = white},
     })
  end

end,
_event_logger_enabled = function(self)
  local logger = Class.ui.menu.misc_tab.event_logger
  local menu = Class.ui.menu.antiaim_tab.additional.fakelag.anti_bruteforce
  if not logger or not menu then
    return false
  end
  local success, enabled = pcall(function()
    return logger.enabled:get()
      and menu.enabled:get()
      and menu.notify:get("Event Logger") == true
  end)
  return success and enabled == true
end,
_notify_reset = function(self, reason)
  local menu = Class.ui.menu.antiaim_tab.additional.fakelag.anti_bruteforce
  local accent = {255, 0, 0}
  reason = tostring(reason or "unknown")
  if Class.misc.notifications_ui and Class.misc.notifications_ui:should_show("Anti-Bruteforce") then
    Class.render.notifications:push(
      "/rAnti-Bruteforce resetted due to /v" .. reason .. "/r",
      "antibrute_reset"
    )
  end
  if self:_event_logger_enabled() then
    Class.misc.event_logger:_emit(accent, {240, 240, 240}, {
      {text = "Anti-Bruteforce resetted due to ", color = {240, 240, 240}},
      {text = reason, color = accent},
    })
  end
end,
get_offset = function(self)
  if not self:_enabled() or not self:_condition_allowed() then
    self:clear()
    return 0
  end
  if self.time == -2 then
    return self.offset
  end
  if self.time < 0 or globals.realtime() >= self.time then
    if self.time >= 0 and self.offset ~= 0 then
      self:_notify_reset("timeout")
    end
    self:clear()
    return 0
  end
  return self.offset
end,
on_setup_command = function(self)
  if not self:_enabled() or not self:_condition_allowed() then
    -- Clear stage, timeout, target and offset as soon as the feature becomes
    -- ineligible. This prevents an old response from reappearing later.
    self:clear()
    return
  end
  if self.time == -2 then
    return
  end
  if self.time >= 0 and globals.realtime() >= self.time then
    if self.offset ~= 0 then
      self:_notify_reset("timeout")
    end
    self:clear()
  end
end,
on_bullet_impact = function(self, event)
  local menu = Class.ui.menu.antiaim_tab.additional.fakelag.anti_bruteforce
  if not menu or not self:_enabled() or not self:_condition_allowed() then
    self:clear()
    return
  end
  local local_player = entity.get_local_player()
  if not local_player or not entity.is_alive(local_player) then
    return
  end
  local shooter = client.userid_to_entindex(event.userid)
  if not shooter or shooter == local_player then
    return
  end
  if not entity.is_alive(shooter) or not entity.is_enemy(shooter) then
    return
  end
  local tick = globals.tickcount()
  if tick == self.tick then
    return
  end
  local origin_x, origin_y, origin_z = entity.get_prop(local_player, "m_vecOrigin")
  if not origin_x then
    return
  end
  local velocity_x, velocity_y, velocity_z = entity.get_prop(local_player, "m_vecVelocity")
  velocity_x = velocity_x or 0
  velocity_y = velocity_y or 0
  velocity_z = velocity_z or 0
  local tick_interval = globals.tickinterval() or 0.015625
  local predicted_x = origin_x + velocity_x * tick_interval * 2
  local predicted_y = origin_y + velocity_y * tick_interval * 2
  local predicted_z = origin_z + velocity_z * tick_interval * 2
  local shooter_x, shooter_y, shooter_z = self:_eye(shooter)
  if not shooter_x or event.x == nil or event.y == nil or event.z == nil then
    return
  end
  local distance = self:_segment_distance(
  shooter_x, shooter_y, shooter_z,
  event.x, event.y, event.z,
  predicted_x, predicted_y, predicted_z
  )
  if distance > 45 then
    return
  end
  self.tick = tick
  self.target = shooter
  self:_set_timeout(menu)
  self.stage = self.stage + 1
  if self.stage >= 15 then
    self.stage = 0
  end
  self.offset = self:_pick_offset(menu)
  -- one shared offset — no side flip / desync spin

  self:_notify(shooter, distance)
end,
on_player_death = function(self, event)
  local victim = client.userid_to_entindex(event.userid)
  local local_player = entity.get_local_player()
  if victim ~= local_player and victim ~= self.target then
    return
  end
  if self.target and victim == self.target and self.offset ~= 0 then
    self:_notify_reset("death")
  end
  self:clear()
end,
}
local function normalize_yaw(angle)
  angle = tonumber(angle) or 0
  while angle > 180 do
    angle = angle - 360
  end
  while angle < -180 do
    angle = angle + 360
  end
  return angle
end

do
  Class.util.antiaim = {
   current_condition = "Shared",
   current_team = "T",
   manual_direction = 0,
   manual_yaw = 0,
   manual_applied = false,
   lr_inverted = false,
   _no_flip_until = 0,
   delay_last_tick = 0,
   delay_counter = 0,
   delay_next = 1,
   custom_delay_index = 1,
   custom_delay_last = 1,
   _freeze_until_tick = 0,
   _last_freeze_tick = -1000000,
   was_in_air = false,
   ways_index = 1,
   ways_tick = 0,
  }
  Class.util.antiaim.conditions = {
   "Shared", "Standing", "Running", "Slowing",
   "Air", "Air Crouch", "Crouch", "Sneaking", "Freestanding", "Legit AA"
  }
  Class.util.antiaim.current_settings = {
   yaw = {
    base = "Local view",
    value = 0,
    left_value = 0,
    right_value = 0,
    modifier = {
     mode = "Off",
     value = 0
    },
  },
  pitch = {
   mode = "Down",
   value = 0,
  },
  fakelag = {
   enabled = true,
   amount = "Maximum",
   limit = 14,
   variance = 0,
  },
  body_yaw = {
   mode = "Off",
   value = 0,
   inverter = false,
   left_value = 0,
   right_value = 0
  },
  break_lc = false,
  freestanding = {
   enabled = false,
   body_yaw = false,
  },
  }
  function Class.util.antiaim.clear_data()
    Class.util.antiaim.current_condition = "Shared"
    Class.util.antiaim.current_team = "T"
    Class.util.antiaim.manual_direction = 0
    Class.util.antiaim.manual_yaw = 0
    Class.util.antiaim.manual_applied = false
    Class.util.antiaim.lr_inverted = false
    Class.util.antiaim.delay_last_tick = 0
    Class.util.antiaim.delay_counter = 0
    Class.util.antiaim.delay_next = 1
    Class.util.antiaim.ways_index = 1
    Class.util.antiaim.ways_tick = 0
    Class.util.antiaim.custom_delay_index = 1
    Class.util.antiaim.custom_delay_last = 1
    Class.util.antiaim._freeze_until_tick = 0
    Class.util.antiaim._last_freeze_tick = -1000000
    Class.util.antiaim._last_applied = {}
    Class.util.antiaim._previous_condition_index = nil
    Class.util.antiaim._prev_team = nil
    Class.util.antiaim.was_in_air = false
    Class.util.antiaim.landing_time = 0
    Class.util.antiaim.freestanding_active = false
    Class.util.antiaim._no_flip_until = 0
    Class.util.antiaim._delay_signature = nil
    Class.util.antiaim._holding_use = false
    Class.util.antiaim._last_choke = nil
    Class.util.antiaim._was_manual = false
    Class.util.antiaim._force_reapply = true
  end

  function Class.util.antiaim.reenable()
    pcall(function()
      local r = Class.util.reference
      if r and r.aa_enabled then
        ui.set(r.aa_enabled, true)
      end
    end)
    Class.util.antiaim._last_applied = {}
    Class.util.antiaim._force_reapply = true
  end
  function Class.util.antiaim.get_next_delay(settings)
    local delay = settings and settings.yaw and settings.yaw.delay
    if not delay or not delay.mode then
      return 1
    end

    local mode = normalize_delay_mode(delay.mode:get())
    if mode == "Disabled" then
      return 1
    end

    if mode == "Custom" then
      local custom = delay.custom
      if not custom or not custom.count or not custom.delays then
        return 1
      end

      local count = math.max(1, tonumber(custom.count:get()) or 1)
      local custom_mode = normalize_custom_delay_mode(custom.mode:get())
      local values = {}
      for index = 1, count do
        local control = custom.delays[index]
        local value = control and tonumber(control:get()) or nil
        if value then
          values[#values + 1] = math.max(1, value)
        end
      end

      if #values == 0 then
        return 1
      end

      if custom_mode == "Sequential" then
        local index = math.min(Class.util.antiaim.custom_delay_index or 1, #values)
        local selected = values[index] or 1
        Class.util.antiaim.custom_delay_index = (index % #values) + 1
        return selected
      end

      if custom_mode == "Smart Random" then
        local candidates = {}
        for index = 1, #values do
          if values[index] ~= Class.util.antiaim.custom_delay_last or #values == 1 then
            candidates[#candidates + 1] = values[index]
          end
        end
        local selected = candidates[math.random(1, #candidates)] or values[1]
        Class.util.antiaim.custom_delay_last = selected
        return selected
      end

      return values[math.random(1, #values)] or 1
    end

    return 1
  end
end
function Class.util.antiaim.get_current_condition(cmd)
  local local_player = entity.get_local_player()
  if local_player == nil then return "Shared" end
  local player_flags = entity.get_prop(local_player, "m_fFlags")
  local player_velocity = { entity.get_prop(local_player, "m_vecVelocity") }
  local player_speed = math.sqrt(player_velocity[1]^2 + player_velocity[2]^2)
  local is_on_ground = bit.band(player_flags, 1) ~= 0
  local is_ducking = entity.get_prop(local_player, "m_flDuckAmount") > 0.7 or ui.get(Class.util.reference.rage_fake_duck[1])
  local is_slow_walking = ui.get(Class.util.reference.aa_slow_walk[1]) and ui.get(Class.util.reference.aa_slow_walk[2])
  if not Class.util.antiaim.landing_time then
    Class.util.antiaim.landing_time = 0
  end
  local was_in_air = Class.util.antiaim.was_in_air or false
  if was_in_air and is_on_ground then
    Class.util.antiaim.landing_time = globals.curtime()
  end
  Class.util.antiaim.was_in_air = not is_on_ground
  local has_recently_landed = (globals.curtime() - Class.util.antiaim.landing_time) < 0.05
  if not is_on_ground then
    if is_ducking then
      return "Air Crouch"
    else
    return "Air"
  end
elseif cmd.in_jump == 1 then
  if is_ducking then
    return "Air Crouch"
  else
  return "Air"
end
elseif has_recently_landed then
  if is_ducking then
    return "Air Crouch"
  else
  return "Air"
end
elseif is_ducking then
  if player_speed > 10 then
    return "Sneaking"
  else
  return "Crouch"
end
elseif is_slow_walking and player_speed > 10 then
  return "Slowing"
elseif player_speed > 5 then
  return "Running"
elseif player_speed <= 5 then
  return "Standing"
else
return "Shared"
end
end
local function is_avoid_backstab_active()
  local extra = Class.ui.menu.antiaim_tab.additional.extra
  local amount = extra.avoid_backstab.amount:get()
  if amount == 0 or not extra.avoid_backstab_enabled:get() then return false end

  local local_player = entity.get_local_player()
  if not local_player or not entity.is_alive(local_player) then return false end

  local lp_origin = { entity.get_prop(local_player, "m_vecOrigin") }
  local backstab_distance = amount
  local players = entity.get_players(true)

  for index = 1, #players do
    local enemy = players[index]
    local active_weapon = entity.get_player_weapon(enemy)
    if active_weapon and entity.get_classname(active_weapon) == "CKnife" then
      local enemy_position = { entity.get_prop(enemy, "m_vecOrigin") }
      local dx = lp_origin[1] - enemy_position[1]
      local dy = lp_origin[2] - enemy_position[2]
      local dz = lp_origin[3] - enemy_position[3]
      local enemy_distance = math.sqrt(dx * dx + dy * dy + dz * dz)

      if enemy_distance <= backstab_distance then
        return true
      end
    end
  end

  return false
end
local function apply_avoid_backstab()
  local aa = Class.util.antiaim
  local settings = aa.current_settings
  local source = nil
  local team = aa.current_team
  local condition_index = tonumber(aa.current_condition_index) or 1
  if team == "T" then
    source = Class.ui.antiaim_conditions_t[condition_index]
  else
    source = Class.ui.antiaim_conditions_ct[condition_index]
  end

  local source_yaw_mode = "180"
  pcall(function()
    if source and source.yaw and source.yaw.mode then
      source_yaw_mode = source.yaw.mode:get() or "180"
    end
  end)

  settings.yaw.base = "At targets"
  settings.yaw.modifier.mode = "Off"
  settings.yaw.modifier.value = 0

  if source_yaw_mode == "L/R" and source and source.yaw then
    local left_value, right_value = 0, 0
    pcall(function() left_value = tonumber(source.yaw.left_value:get()) or 0 end)
    pcall(function() right_value = tonumber(source.yaw.right_value:get()) or 0 end)
    settings.yaw.mode = "L/R"
    settings.yaw.left_value = normalize_yaw(left_value + 180)
    settings.yaw.right_value = normalize_yaw(right_value + 180)
  else
    settings.yaw.mode = "180"
    settings.yaw.value = 180
  end

  -- Body Yaw remains inherited from the active Builder condition. L/R mode
  -- keeps the Builder Delay scheduler; yaw variability is intentionally ignored.
  settings.freestanding.enabled = false
end
local function is_fast_ladder_active()
  if not Class.ui.menu.antiaim_tab.additional.extra.fast_ladder_enabled:get() then return false end
  local local_player = entity.get_local_player()
  if not local_player or not entity.is_alive(local_player) then return false end
  if entity.get_prop(local_player, "m_MoveType") ~= 9 then return false end
  local active_weapon = entity.get_player_weapon(local_player)
  if not active_weapon then return false end
  local throw_time = entity.get_prop(active_weapon, "m_fThrowTime")
  if throw_time ~= nil and throw_time ~= 0 then return false end
  return true
end
local function apply_fast_ladder(cmd)
  if cmd.forwardmove > 0 then
    if cmd.pitch < 45 then
      cmd.pitch = 89
      cmd.in_moveright = 1
      cmd.in_moveleft = 0
      cmd.in_forward = 0
      cmd.in_back = 1
      if cmd.sidemove == 0 then
        cmd.yaw = cmd.yaw + 90
      end
      if cmd.sidemove < 0 then
        cmd.yaw = cmd.yaw + 150
      end
      if cmd.sidemove > 0 then
        cmd.yaw = cmd.yaw + 30
      end
    end
  elseif cmd.forwardmove < 0 then
    cmd.pitch = 89
    cmd.in_moveleft = 1
    cmd.in_moveright = 0
    cmd.in_forward = 1
    cmd.in_back = 0
    if cmd.sidemove == 0 then
      cmd.yaw = cmd.yaw + 90
    end
    if cmd.sidemove > 0 then
      cmd.yaw = cmd.yaw + 150
    end
    if cmd.sidemove < 0 then
      cmd.yaw = cmd.yaw + 30
    end
  end
end
local fast_ladder_avoid_state = {
  duck_ticks = 0
}

local function reset_fast_ladder_avoid_state()
  fast_ladder_avoid_state.duck_ticks = 0
end

local FAST_LADDER_CONTENTS_LADDER = 536870912
local FAST_LADDER_CONTENTS_PLAYERCLIP = 65536
local FAST_LADDER_MASK_PLAYERSOLID = 33636363

local function update_fast_ladder_avoid(cmd)
  local extra = Class.ui.menu.antiaim_tab.additional.extra
  local enabled = extra and extra.fast_ladder_enabled and extra.fast_ladder_avoid
    and extra.fast_ladder_enabled:get() and extra.fast_ladder_avoid:get()

  local state = fast_ladder_avoid_state
  if not enabled or not cmd then
    state.duck_ticks = 0
    return
  end

  local me = entity.get_local_player()
  if not me or not entity.is_alive(me) then
    state.duck_ticks = 0
    return
  end

  local move_type = entity.get_prop(me, "m_MoveType")
  if move_type == 9 then
    local nx, ny, nz = entity.get_prop(me, "m_vecLadderNormal")
    local ox, oy, oz = entity.get_origin(me)
    local vx, vy, vz = entity.get_prop(me, "m_vecVelocity")
    local minx, miny, minz = entity.get_prop(me, "m_vecMins")
    local maxx, maxy, maxz = entity.get_prop(me, "m_vecMaxs")

    if nx ~= nil and ny ~= nil and nz ~= nil
      and ox ~= nil and oy ~= nil and oz ~= nil
      and vx ~= nil and vy ~= nil and vz ~= nil
      and minx ~= nil and miny ~= nil and minz ~= nil
      and maxx ~= nil and maxy ~= nil and maxz ~= nil
    then
      local normal = -vector(nx, ny, nz)
      local origin = vector(ox, oy, oz)
      local velocity = vector(vx, vy, vz)
      local mins = vector(minx, miny, minz)
      local maxs = vector(maxx, maxy, maxz)

      if normal:lengthsqr() > 0 then
        local tickinterval = globals.tickinterval()
        local gravity = cvar.sv_gravity:get_float() * 0.4
        local half_gravity = gravity * tickinterval * 0.5
        local move_step = vector(
          velocity.x * tickinterval,
          velocity.y * tickinterval,
          (velocity.z - half_gravity) * tickinterval
        )
        velocity.z = velocity.z - gravity * tickinterval

        local predicted_origin = origin + move_step
        local ladder_trace = trace.hull(
          predicted_origin,
          predicted_origin + normal:normalized() * 12,
          mins,
          maxs,
          {
            skip = me,
            mask = bit.band(FAST_LADDER_MASK_PLAYERSOLID, bit.bnot(FAST_LADDER_CONTENTS_PLAYERCLIP))
          }
        )

        local is_going_up = velocity.z > 0
        local on_ladder = move_type == 9
        local will_be_on_edge = ladder_trace ~= nil
          and ladder_trace.fraction ~= 0
          and bit.band(ladder_trace.contents or 0, FAST_LADDER_CONTENTS_LADDER) == 0

        if is_going_up and on_ladder and will_be_on_edge then
          state.duck_ticks = 3
        end
      end
    end
  end

  if state.duck_ticks > 0 then
    cmd.in_duck = 1
    state.duck_ticks = state.duck_ticks - 1
  end
end

local MANUAL_YAWS = { -90, 90, 180 }

local function get_manual_hotkey_input(element)
  if not element or not element.ref then
    return false, nil, nil
  end

  local ok, active, mode, key = pcall(ui.get, element.ref)
  if not ok then
    return false, nil, nil
  end

  if type(key) ~= "number" then
    key = tonumber(key)
  end

  return active == true, mode, key
end

local function normalize_manual_hotkey_mode(mode)
  if type(mode) == "number" then
    if mode == 0 then return "always on" end
    if mode == 1 then return "on hotkey" end
    if mode == 2 then return "toggle" end
    if mode == 3 then return "off hotkey" end
  end

  local value = tostring(mode or "on hotkey"):lower()
  value = value:gsub("[%s_%-]+", "")
  return value
end

local function manual_direction()
  local state = Class.util.antiaim
  local hotkeys = Class.ui.menu.antiaim_tab.additional.hotkey
  local elements = {
    hotkeys.manual_left,
    hotkeys.manual_right,
    hotkeys.manual_forward,
  }

  state.manual_key_down = state.manual_key_down or {false, false, false}
  state.manual_toggle_state = state.manual_toggle_state or {false, false, false}
  state.manual_key_code = state.manual_key_code or {nil, nil, nil}

  local selected = state.manual_direction or 0

  for index = 1, 3 do
    local ui_active, mode, key = get_manual_hotkey_input(elements[index])
    local normalized_mode = normalize_manual_hotkey_mode(mode)

    local down = false
    if key ~= nil then
      if state.manual_key_code[index] ~= key then
        state.manual_key_code[index] = key
        state.manual_key_down[index] = false
      end

      local ok, physical_down = pcall(client.key_state, key)
      down = ok and physical_down == true or false
    end

    if normalized_mode == "toggle" then
      if down and not state.manual_key_down[index] then
        selected = selected == index and 0 or index
      end
    elseif normalized_mode == "onhotkey" then
      if down then
        selected = index
      elseif selected == index then
        selected = 0
      end
      state.manual_toggle_state[index] = false
    elseif normalized_mode == "offhotkey" then
      if key ~= nil and not down then
        selected = index
      elseif selected == index then
        selected = 0
      end
      state.manual_toggle_state[index] = false
    elseif normalized_mode == "alwayson" then
      selected = index
      state.manual_toggle_state[index] = false
    else
      if ui_active then
        selected = index
      elseif selected == index then
        selected = 0
      end
      state.manual_toggle_state[index] = false
    end

    state.manual_key_down[index] = down
  end

  state.manual_direction = selected
  state.manual_yaw = selected ~= 0 and MANUAL_YAWS[selected] or 0
end
local function apply_manual_settings()
  local state = Class.util.antiaim
  local manual_dir = state.manual_direction
  local manual_yaw = tonumber(state.manual_yaw) or 0

  if manual_dir == 0 or manual_yaw == 0 then
    return
  end

  local mode = Class.ui.menu.antiaim_tab.additional.hotkey.manual_mode:get() or "Builder"
  local settings = state.current_settings

  settings.yaw.mode = "180"
  settings.yaw.base = "Local view"
  settings.yaw.value = manual_yaw
  settings.yaw.left_value = manual_yaw
  settings.yaw.right_value = manual_yaw
  settings.freestanding.enabled = false

  if mode == "Builder" then
    return
  end

  settings.yaw.modifier.mode = "Off"
  settings.yaw.modifier.value = 0
  settings.body_yaw.mode = mode == "Jitter" and "Jitter" or "Static"

  if manual_dir == 1 then
    settings.body_yaw.value = -60
  elseif manual_dir == 2 then
    settings.body_yaw.value = 60
  else
    settings.body_yaw.value = 0
  end
end
local function prefer_manual_enabled()
  local control = Class.ui.menu.antiaim_tab.additional.hotkey.prefer_manual
  if not control then return true end
  local ok, value = pcall(control.get, control)
  if not ok or value == nil then return true end
  return value == true or value == 1
end
local function is_freestanding_active()
  if Class.util.antiaim.manual_direction ~= 0 and prefer_manual_enabled() then return false end
  return Class.util.antiaim.freestanding_active and true or false
end
local function apply_freestanding(enabled)
  local settings = Class.util.antiaim.current_settings
  settings.freestanding.enabled = enabled and true or false
  settings.freestanding.body_yaw = settings.freestanding.enabled
    and settings.body_yaw and settings.body_yaw.mode == "Jitter"
    and settings.freestanding.body_yaw and true or false
end
local function is_safe_head_active()
  local safe_head = Class.ui.menu.antiaim_tab.additional.extra
  if not safe_head or not safe_head.safe_head_enabled:get() then
    return false
  end

  local local_player = entity.get_local_player()
  if not local_player or not entity.is_alive(local_player) then
    return false
  end

  local active_weapon = entity.get_player_weapon(local_player)
  if not active_weapon then
    return false
  end

  local current_threat = client.current_threat()
  if not current_threat or not entity.is_alive(current_threat) then
    return false
  end

  local _, _, player_z = entity.get_prop(local_player, "m_vecOrigin")
  local _, _, enemy_z = entity.get_prop(current_threat, "m_vecOrigin")
  if not player_z or not enemy_z then
    return false
  end

  local flags = tonumber(entity.get_prop(local_player, "m_fFlags")) or 0
  local on_ground = bit.band(flags, 1) ~= 0
  local duck_amount = tonumber(entity.get_prop(local_player, "m_flDuckAmount")) or 0
  local weapon_class = entity.get_classname(active_weapon)
  local conditions = safe_head.safe_head.conditions

  if conditions:get("Air Crouch") and not on_ground and duck_amount > 0 then
    return true
  end

  if conditions:get("Crouch") and on_ground and duck_amount > 0 then
    return true
  end

  if conditions:get("Taser") and weapon_class == "CWeaponTaser" then
    return true
  end

  if conditions:get("Knife") and weapon_class == "CKnife" then
    return true
  end

  local height_difference = player_z - enemy_z
  local height_difference_limit = tonumber(safe_head.safe_head.height_difference:get()) or 25
  if conditions:get("Above enemy") and height_difference >= height_difference_limit then
    return true
  end

  return false
end

local function apply_safe_head()
  Class.util.antiaim.current_settings.pitch.mode = "Down"
  Class.util.antiaim.current_settings.yaw.mode = "180"
  Class.util.antiaim.current_settings.yaw.value = 0
  Class.util.antiaim.current_settings.yaw.base = "At targets"
  Class.util.antiaim.current_settings.yaw.modifier.mode = "Off"
  Class.util.antiaim.current_settings.yaw.modifier.value = 0
  Class.util.antiaim.current_settings.body_yaw.mode = "Static"
  Class.util.antiaim.current_settings.body_yaw.value = 0
  Class.util.antiaim.current_settings.freestanding.enabled = false
end
function Class.util.antiaim.load_builder_settings(cmd, current_condition_index, player_team)
  local settings = (player_team == "T") and Class.ui.antiaim_conditions_t[current_condition_index] or Class.ui.antiaim_conditions_ct[current_condition_index]
  if not settings or not settings.yaw then
    settings = (player_team == "T") and Class.ui.antiaim_conditions_t[1] or Class.ui.antiaim_conditions_ct[1]
  end
  if not settings or not settings.yaw then return end
  local yaw_variability_percent = math.max(0, math.min(100, settings.yaw.variability_value:get() or 0))
  local yaw_modifier_variability_percent = math.max(0, math.min(100, settings.yaw.modifier.variability_value:get() or 0))
  local yaw_variability_limit = math.floor(180 * yaw_variability_percent / 100 + 0.5)
  local yaw_modifier_variability_limit = math.floor(180 * yaw_modifier_variability_percent / 100 + 0.5)
  local yaw_variability_value = math.random(-yaw_variability_limit, yaw_variability_limit)
  local yaw_modifier_variability_value = math.random(-yaw_modifier_variability_limit, yaw_modifier_variability_limit)
  if settings.pitch and settings.pitch.mode then
    pcall(function()
      Class.util.antiaim.current_settings.pitch.mode = settings.pitch.mode:get()
      Class.util.antiaim.current_settings.pitch.value = settings.pitch.value:get()
    end)
  end
  if settings.yaw and settings.yaw.base then
    pcall(function()
      Class.util.antiaim.current_settings.yaw.base = settings.yaw.base:get()
    end)
  else
    Class.util.antiaim.current_settings.yaw.base = "Local view"
  end
  Class.util.antiaim.current_settings.yaw.mode = settings.yaw.mode:get()
  Class.util.antiaim.current_settings.yaw.value = normalize_yaw(settings.yaw.value:get() + yaw_variability_value)
  Class.util.antiaim.current_settings.yaw.left_value = normalize_yaw(settings.yaw.left_value:get() + yaw_variability_value)
  Class.util.antiaim.current_settings.yaw.right_value = normalize_yaw(settings.yaw.right_value:get() + yaw_variability_value)
  local mod_mode = settings.yaw.modifier.mode:get()
  local mod_val = normalize_yaw(settings.yaw.modifier.value:get() + yaw_modifier_variability_value)
  if mod_mode == "G0BLIN" then
    local phase = math.floor(globals.realtime() * 5) % 2
    mod_val = normalize_yaw((phase == 0) and settings.yaw.modifier.value:get() or -settings.yaw.modifier.value:get())
    mod_mode = "Offset"
  elseif mod_mode == "Ways" then
    local w = tonumber(settings.yaw.modifier.ways:get()) or 1
    local n = math.max(1, math.min(12, math.floor(w)))
    Class.util.antiaim.ways_index = math.max(1, math.min(n, tonumber(Class.util.antiaim.ways_index) or 1))
    Class.util.antiaim.ways_tick = Class.util.antiaim.ways_tick or 0
    Class.util.antiaim.ways_tick = Class.util.antiaim.ways_tick + 1
    if Class.util.antiaim.ways_tick >= 2 then
      Class.util.antiaim.ways_index = (Class.util.antiaim.ways_index % n) + 1
      Class.util.antiaim.ways_tick = 0
    end
    local index = Class.util.antiaim.ways_index
    local way_val = 0
    if settings.yaw.modifier.ways_offsets and settings.yaw.modifier.ways_offsets[index] then
      local off = settings.yaw.modifier.ways_offsets[index]
      if off and off.get then
        way_val = off:get()
      end
    end
    mod_mode = "Offset"
    mod_val = normalize_yaw(way_val)
  end
  Class.util.antiaim.current_settings.yaw.modifier.mode = mod_mode
  Class.util.antiaim.current_settings.yaw.modifier.value = mod_val
  Class.util.antiaim.current_settings.body_yaw.mode = settings.body_yaw.mode:get()
  Class.util.antiaim.current_settings.body_yaw.value = settings.body_yaw.value:get()
  Class.util.antiaim.current_settings.body_yaw.left_value = settings.body_yaw.left_value:get()
  Class.util.antiaim.current_settings.body_yaw.right_value = settings.body_yaw.right_value:get()
  Class.util.antiaim.current_settings.body_yaw.inverter = settings.body_yaw.inverter and settings.body_yaw.inverter:get() and true or false
  local builder_body_freestanding = false
  pcall(function()
    builder_body_freestanding = settings.body_yaw.mode:get() == "Jitter"
      and Class.ui.menu.antiaim_tab.additional.hotkey.body_freestanding:get() and true or false
  end)
  Class.util.antiaim.current_settings.freestanding.body_yaw = builder_body_freestanding
  local force_defensive_enabled = false
  pcall(function()
    force_defensive_enabled = settings.force_defensive and settings.force_defensive:get() and true or false
  end)
  Class.util.antiaim.current_settings.break_lc = force_defensive_enabled
  local function update_yaw_delay()
    local tick = globals.tickcount() or 0
    local anti_aim = Class.util.antiaim

    local yaw_mode = anti_aim.current_settings.yaw.mode
    -- Custom Desync timing is only used by L/R. Native 180 yaw must remain untouched.
    if yaw_mode ~= "L/R" then
      return
    end

    if anti_aim._delay_yaw_mode ~= yaw_mode then
      anti_aim._delay_yaw_mode = yaw_mode
    end

    anti_aim.delay_counter = tonumber(anti_aim.delay_counter) or 0
    anti_aim.delay_last_tick = tonumber(anti_aim.delay_last_tick) or anti_aim.delay_counter

    local delay = settings.yaw.delay
    local freeze_enabled = false
    pcall(function()
      freeze_enabled = delay.features and delay.features:get("Freeze Inverter") and true or false
    end)
    local freeze_chance = math.max(0, math.min(100, tonumber(delay.freeze_chance and delay.freeze_chance:get()) or 30))
    local freeze_time = math.max(0, math.floor(tonumber(delay.freeze_time and delay.freeze_time:get()) or 10))
    local freeze_cooldown = math.max(0, math.floor(tonumber(delay.freeze_cooldown and delay.freeze_cooldown:get()) or 1))
    local disabling_enabled = false
    pcall(function()
      disabling_enabled = delay.features and delay.features:get("Disabling") and true or false
    end)
    local disabling_chance = math.max(0, math.min(100, tonumber(delay.disabling_chance and delay.disabling_chance:get()) or 30))
    local disabling_time = math.max(0, math.floor(tonumber(delay.disabling_time and delay.disabling_time:get()) or 10))
    local signature_parts = {
      tostring(anti_aim.current_condition or "Shared"),
      tostring(yaw_mode),
      tostring(delay.mode:get()),
      tostring(delay.custom.mode:get()),
      tostring(delay.custom.count:get()),
      tostring(freeze_enabled), tostring(freeze_chance), tostring(freeze_time), tostring(freeze_cooldown),
      tostring(disabling_enabled), tostring(disabling_chance), tostring(disabling_time),
      (function()
        local a = false
        pcall(function() a = delay.features and delay.features:get("Affect Modifier to Delay") end)
        return tostring(a)
      end)(),
    }
    local configured_count = math.max(1, math.min(12, tonumber(delay.custom.count:get()) or 1))
    for delay_index = 1, configured_count do
      local control = delay.custom.delays and delay.custom.delays[delay_index]
      signature_parts[#signature_parts + 1] = tostring(control and control:get() or 1)
    end
    local signature = table.concat(signature_parts, ":")

    if signature ~= anti_aim._delay_signature then
      anti_aim._delay_signature = signature
      anti_aim.custom_delay_index = 1
      anti_aim.custom_delay_last = nil
      anti_aim._freeze_until_tick = 0
      anti_aim._last_freeze_tick = -1000000
      anti_aim.delay_next = anti_aim.get_next_delay(settings)
      anti_aim.delay_last_tick = anti_aim.delay_counter
      return
    end

    local exploit_active = false
    pcall(function()
      local reference = Class.util.reference.rage_double_tap
      if reference and reference[1] and reference[2] then
        exploit_active = ui.get(reference[1]) and ui.get(reference[2]) and true or false
      end
    end)
    -- Disabling window: delay is OFF → flip every eligible tick
    local delay_off = false
    if disabling_enabled then
      local until_t = tonumber(anti_aim._disable_until_tick) or 0
      if tick < until_t then
        delay_off = true
      end
    end

    if not cmd or (tonumber(cmd.chokedcommands) or 0) ~= 0 then
      return
    end
    if anti_aim._no_flip_until and tick < anti_aim._no_flip_until then
      return
    end
    if anti_aim._holding_use and anti_aim.current_condition ~= "Legit AA" then
      return
    end

    anti_aim.delay_counter = anti_aim.delay_counter + 1

    if not delay_off and freeze_enabled then
      if tick < (tonumber(anti_aim._freeze_until_tick) or 0) then
        return
      end
      anti_aim._freeze_until_tick = 0
    end

    local switch_delay = delay_off and 1 or math.max(1, math.floor(tonumber(anti_aim.delay_next) or 1))
    if anti_aim.delay_counter - anti_aim.delay_last_tick < switch_delay then
      return
    end

    -- roll chance to turn delay OFF for Disabling Time
    if disabling_enabled and not delay_off and disabling_chance > 0 and disabling_time > 0 then
      if math.random(1, 100) <= disabling_chance then
        anti_aim._disable_until_tick = tick + disabling_time
        delay_off = true
        switch_delay = 1
      end
    end

    anti_aim.lr_inverted = not anti_aim.lr_inverted
    anti_aim.delay_last_tick = anti_aim.delay_counter
    anti_aim.delay_next = delay_off and 1 or anti_aim.get_next_delay(settings)

    local affect_modifier = false
    pcall(function()
      affect_modifier = delay.features and delay.features:get("Affect Modifier to Delay") and true or false
    end)
    if affect_modifier then
      anti_aim._mod_delay_flip = not (anti_aim._mod_delay_flip and true or false)
    end

    if not delay_off and freeze_enabled and freeze_chance > 0 and freeze_time > 0 then
      local cooldown_ready = freeze_cooldown <= 0 or tick - (tonumber(anti_aim._last_freeze_tick) or -1000000) >= freeze_cooldown
      if cooldown_ready and math.random(1, 100) <= freeze_chance then
        anti_aim._last_freeze_tick = tick
        anti_aim._freeze_until_tick = tick + freeze_time
      end
    end
  end
  if Class.util.antiaim.current_settings.yaw.mode == "180" then
    local body_mode = Class.util.antiaim.current_settings.body_yaw.mode
    if body_mode == "Disabled" then body_mode = "Off" end
    local raw = tonumber(settings.body_yaw.value:get()) or 0
    if raw > 180 then raw = 180 elseif raw < -180 then raw = -180 end
    if body_mode == "Opposite" then
      Class.util.antiaim.current_settings.body_yaw.mode = "Opposite"
      Class.util.antiaim.current_settings.body_yaw.value = 0
    elseif body_mode == "Jitter" then
      Class.util.antiaim.current_settings.body_yaw.mode = "Jitter"
      Class.util.antiaim.current_settings.body_yaw.value = raw
    elseif body_mode == "Static" then
      Class.util.antiaim.current_settings.body_yaw.mode = "Static"
      local mag = 60
      local dir = "Right"
      pcall(function()
        if settings.body_yaw.direction then dir = settings.body_yaw.direction:get() or "Right" end
      end)
      Class.util.antiaim.current_settings.body_yaw.value = (dir == "Left") and -mag or mag
    else
      Class.util.antiaim.current_settings.body_yaw.mode = "Off"
      Class.util.antiaim.current_settings.body_yaw.value = 0
    end
  end
  if Class.util.antiaim.current_settings.yaw.mode == "L/R" then
    update_yaw_delay()
    Class.util.antiaim.current_settings.body_yaw.mode = "Static"
    do
      local body_left = tonumber(Class.util.antiaim.current_settings.body_yaw.left_value) or 0
      local body_right = tonumber(Class.util.antiaim.current_settings.body_yaw.right_value) or 0
      local body_val = Class.util.antiaim.lr_inverted and -body_left or body_right
      if Class.util.antiaim.current_settings.body_yaw.inverter then
        body_val = -body_val
      end
      Class.util.antiaim.current_settings.body_yaw.value = body_val
    end
  end
end
Class.util.antiaim._last_applied = Class.util.antiaim._last_applied or {}
local is_warmup_aa_active
local function _aa_set(key, reference, value)
  if reference == nil then return end
  local last = Class.util.antiaim._last_applied
  local force = Class.util.antiaim._force_reapply
  if force or last[key] ~= value then
    local success = pcall(ui.set, reference, value)
    if success then
      last[key] = value
    end
  else
    if key == "yaw_val" or key == "body_val" or key == "pitch_val" or key == "yaw_mode" or key == "body_mode" or key == "pitch_mode" then
      pcall(ui.set, reference, value)
    end
  end
end
-- Есть ли рядом то, что можно использовать на E (дверь, кнопка, заложник, брошенное оружие).
-- Повторяет логику движка: дистанция <= 96 и угол до центра объекта ~ <= 37 градусов (dot >= 0.8).
do
  local USE_RANGE, USE_DOT = 96, 0.8
  local USE_CLASSES = { "CPropDoorRotating", "CBaseDoor", "CBaseButton", "CHostage" }
  local weapon_cache, weapon_cache_tick = {}, -1

  local function is_weapon_class(name)
    return name ~= nil and (name:find("^CWeapon") ~= nil or name == "CAK47" or name == "CDEagle"
      or name == "CKnife" or name == "CC4" or name:find("Grenade$") ~= nil or name == "CFlashbang"
      or name == "CDecoyGrenade" or name == "CSensorGrenade")
  end

  local function dropped_weapons()
    local tick = globals.tickcount()
    if tick - weapon_cache_tick < 16 then return weapon_cache end
    weapon_cache_tick = tick
    weapon_cache = {}
    for _, ent in ipairs(entity.get_all()) do
      if is_weapon_class(entity.get_classname(ent)) and entity.get_prop(ent, "m_iState") == 0 then
        weapon_cache[#weapon_cache + 1] = ent
      end
    end
    return weapon_cache
  end

  local function center_of(ent)
    local ox, oy, oz = entity.get_origin(ent)
    if not ox then return nil end
    local ok, mins_x, mins_y, mins_z = pcall(entity.get_prop, ent, "m_vecMins")
    local ok2, maxs_x, maxs_y, maxs_z = pcall(entity.get_prop, ent, "m_vecMaxs")
    if ok and ok2 and mins_x and maxs_x then
      return ox + (mins_x + maxs_x) * 0.5, oy + (mins_y + maxs_y) * 0.5, oz + (mins_z + maxs_z) * 0.5
    end
    return ox, oy, oz
  end

  local function usable_near(player, ex, ey, ez, dx, dy, dz, ent)
    local cx, cy, cz = center_of(ent)
    if not cx then return false end
    local vx, vy, vz = cx - ex, cy - ey, cz - ez
    local dist = math.sqrt(vx * vx + vy * vy + vz * vz)
    if dist > USE_RANGE or dist < 1 then return false end
    if (vx * dx + vy * dy + vz * dz) / dist < USE_DOT then return false end
    local tr = trace.line(vector(ex, ey, ez), vector(cx, cy, cz), { skip = player })
    if not tr then return false end
    local fraction = tonumber(tr.fraction) or 0
    if fraction >= 0.99 then return true end
    local hit = nil
    pcall(function() hit = tr.entity end)
    if hit == nil then pcall(function() hit = tr.ent end) end
    if hit == nil then pcall(function() hit = tr.entindex end) end
    if hit == nil and type(tr) == "table" then
      hit = tr.entity or tr.ent or tr.entindex
    end
    if type(hit) == "number" then
      return hit == ent or hit == entity.get_player_resource()
    end
    return hit == ent
  end

  function Class.util.antiaim.has_use_target(player, cmd)
    local ex, ey, ez = client.eye_position()
    if not ex then return false end
    local pitch, yaw = math.rad(tonumber(cmd.pitch) or 0), math.rad(tonumber(cmd.yaw) or 0)
    local dx, dy, dz = math.cos(pitch) * math.cos(yaw), math.cos(pitch) * math.sin(yaw), -math.sin(pitch)
    for _, class in ipairs(USE_CLASSES) do
      for _, ent in ipairs(entity.get_all(class)) do
        if usable_near(player, ex, ey, ez, dx, dy, dz, ent) then return true end
      end
    end
    for _, ent in ipairs(dropped_weapons()) do
      if usable_near(player, ex, ey, ez, dx, dy, dz, ent) then return true end
    end
    return false
  end
end

function Class.util.antiaim.apply_native_settings()
  local s = Class.util.antiaim.current_settings
  local r = Class.util.reference
  local warmup_on = false
  if is_warmup_aa_active then
    pcall(function() warmup_on = is_warmup_aa_active() and true or false end)
  end
  if warmup_on and Class.util.antiaim._holding_use then
    warmup_on = false
  end
  local anti_bruteforce = nil
  if not warmup_on and Class.antiaim then
    anti_bruteforce = Class.antiaim.anti_bruteforce
  end
  if warmup_on then
    -- Warmup AA is the base preset. Manual directions and freestanding are
    -- applied afterward so their native controls are not overwritten here.
    local warmup = Class.ui.menu.antiaim_tab.additional.extra.warmup
    local speed, range, yaw_mode, pitch_mode = 10, 180, "Spin", "Down"
    pcall(function()
      speed = tonumber(warmup.speed:get()) or 10
      range = tonumber(warmup.range:get()) or 180
      yaw_mode = warmup.yaw_mode:get()
      pitch_mode = warmup.pitch:get()
    end)
    speed = math.max(1, math.min(100, speed))
    range = math.max(1, math.min(180, range))

    local manual_requested = (tonumber(Class.util.antiaim.manual_direction) or 0) ~= 0
    local freestanding_enabled = s.freestanding and s.freestanding.enabled and true or false
    local manual_active = manual_requested and (prefer_manual_enabled() or not freestanding_enabled)
    Class.util.antiaim.manual_applied = manual_active and true or false
    local freestanding_body = freestanding_enabled and s.freestanding
      and s.freestanding.body_yaw and s.body_yaw
      and s.body_yaw.mode == "Jitter" and true or false
    -- Prefer Manual decides which bind owns yaw when both are active.
    -- With Prefer Manual off, native Freestanding takes priority over Manual.

    _aa_set("pitch_mode", r.aa_pitch[1], pitch_mode == "Disabled" and "Off" or pitch_mode)
    if manual_active then
      -- Manual direction takes control of yaw while Warmup pitch and spin
      -- remain the base whenever no manual direction is active.
      _aa_set("yaw_base", r.aa_yaw_base, s.yaw.base or "Local view")
      if s.yaw.mode == "L/R" then
        _aa_set("yaw_mode", r.aa_yaw[1], "180")
        local left_v = tonumber(s.yaw.left_value) or 0
        local right_v = tonumber(s.yaw.right_value) or 0
        local base = Class.util.antiaim.lr_inverted and left_v or right_v
        _aa_set("yaw_val", r.aa_yaw[2], normalize_yaw(base))
      elseif s.yaw.mode == "180" then
        _aa_set("yaw_mode", r.aa_yaw[1], "180")
        _aa_set("yaw_val", r.aa_yaw[2], normalize_yaw(tonumber(s.yaw.value) or 0))
      else
        _aa_set("yaw_mode", r.aa_yaw[1], s.yaw.mode or "Static")
        _aa_set("yaw_val", r.aa_yaw[2], normalize_yaw(tonumber(s.yaw.value) or 0))
      end
      _aa_set("jitter_mode", r.aa_yaw_jitter[1], s.yaw.modifier.mode or "Off")
      _aa_set("jitter_val", r.aa_yaw_jitter[2], tonumber(s.yaw.modifier.value) or 0)

      -- Body Yaw is owned by Warmup AA and must stay Off while it is active.
      -- Manual only changes yaw; it never overrides Warmup Body Yaw.
    else
      -- No manual direction: keep the Warmup spin active.
      local curtime = tonumber(globals.curtime()) or 0
      local yaw_offset
      if yaw_mode == "Distortion" then
        yaw_offset = math.sin(math.rad(curtime * speed * 18)) * range
      else
        yaw_offset = (curtime * speed * 36) % (range * 2) - range
      end

      _aa_set("yaw_base", r.aa_yaw_base, "Local view")
      _aa_set("yaw_mode", r.aa_yaw[1], "Static")
      _aa_set("yaw_val", r.aa_yaw[2], normalize_yaw(yaw_offset))
      _aa_set("jitter_mode", r.aa_yaw_jitter[1], "Off")
      _aa_set("body_mode", r.aa_yaw_body[1], "Off")
      _aa_set("body_val", r.aa_yaw_body[2], 0)
      if r.aa_yaw_body and r.aa_yaw_body[2] then
        pcall(ui.set, r.aa_yaw_body[2], 0)
      end
    end

    -- Lock Body Yaw to the Warmup preset (Off) even while Manual or
    -- Freestanding is active. Also block the native Freestanding Body Yaw
    -- option, which can otherwise re-enable a body-yaw override by itself.
    _aa_set("body_mode", r.aa_yaw_body and r.aa_yaw_body[1], "Off")
    _aa_set("body_val", r.aa_yaw_body and r.aa_yaw_body[2], 0)
    if r.aa_yaw_body and r.aa_yaw_body[1] then
      pcall(ui.set, r.aa_yaw_body[1], "Off")
    end
    if r.aa_yaw_body and r.aa_yaw_body[2] then
      pcall(ui.set, r.aa_yaw_body[2], 0)
    end
    freestanding_body = false

    -- Keep native Freestanding available during Warmup AA. Prefer Manual
    -- decides whether the Manual bind suppresses Freestanding or lets it overlay.
    if r.aa_freestanding and r.aa_freestanding[1] then
      pcall(ui.set, r.aa_freestanding[1], freestanding_enabled)
      if r.aa_freestanding[2] then
        if freestanding_enabled then pcall(ui.set, r.aa_freestanding[2], "Always on") end
      end
    end
    Class.util.antiaim._last_applied["freestanding"] = freestanding_enabled

    if manual_active then
      freestanding_body = false
    end
    if r.aa_fs_body_yaw then
      pcall(ui.set, r.aa_fs_body_yaw, freestanding_body)
    end
    Class.util.antiaim._last_applied["freestanding_body"] = freestanding_body
  else
    local pitch_mode = s.pitch.mode
    local pitch_value = s.pitch.value
    if Class.util.antiaim.current_condition == "Legit AA" then
      -- Legit AA: pitch не трогаем, движок отдаёт текущий pitch камеры без задержки
      pitch_mode = "Off"
    elseif pitch_mode == "Off" then
      pitch_mode = "Custom"
      pitch_value = 0
    end
    _aa_set("pitch_mode", r.aa_pitch[1], pitch_mode)
    _aa_set("pitch_val", r.aa_pitch[2], pitch_value)
    _aa_set("yaw_base", r.aa_yaw_base, s.yaw.base or "Local view")
    -- Anti-bruteforce: pure yaw offset (no body invert / no side targeting)
    local ab_offset = 0
    if anti_bruteforce and anti_bruteforce.get_offset then
      ab_offset = tonumber(anti_bruteforce:get_offset()) or 0
    end
    if s.yaw.mode == "L/R" then
      _aa_set("yaw_mode", r.aa_yaw[1], "180")
      local left_v = tonumber(s.yaw.left_value) or 0
      local right_v = tonumber(s.yaw.right_value) or 0
      local use_left = Class.util.antiaim.lr_inverted and true or false
      local base = use_left and left_v or right_v
      _aa_set("yaw_val", r.aa_yaw[2], normalize_yaw(base + ab_offset))
    elseif s.yaw.mode == "180" then
      -- Preserve native GameSense 180 mode; no custom Desync/Delay is applied.
      _aa_set("yaw_mode", r.aa_yaw[1], "180")
      local base = tonumber(s.yaw.value) or 0
      _aa_set("yaw_val", r.aa_yaw[2], normalize_yaw(base + ab_offset))
    else
      _aa_set("yaw_mode", r.aa_yaw[1], s.yaw.mode)
      if r.aa_yaw and r.aa_yaw[2] then
        local base = tonumber(s.yaw.value) or 0
        _aa_set("yaw_val", r.aa_yaw[2], normalize_yaw(base + ab_offset))
      end
    end
    _aa_set("jitter_mode", r.aa_yaw_jitter[1], s.yaw.modifier.mode)
    _aa_set("jitter_val", r.aa_yaw_jitter[2], s.yaw.modifier.value)
    local freestanding_enabled = s.freestanding and s.freestanding.enabled and true or false
    local body_mode = s.body_yaw.mode or "Off"
    local body_val = tonumber(s.body_yaw.value) or 0
    local body_freestanding_enabled = freestanding_enabled and body_mode == "Jitter"
      and s.freestanding and s.freestanding.body_yaw and true or false
    if body_mode == "Jitter" or body_mode == "Static" or body_mode == "Off" or body_mode == "Opposite" then
      _aa_set("body_mode", r.aa_yaw_body[1], body_mode)
      if body_mode == "Off" then
        _aa_set("body_val", r.aa_yaw_body[2], 0)
        if r.aa_yaw_body and r.aa_yaw_body[2] then pcall(ui.set, r.aa_yaw_body[2], 0) end
      else
        _aa_set("body_val", r.aa_yaw_body[2], body_val)
        if r.aa_yaw_body and r.aa_yaw_body[2] then pcall(ui.set, r.aa_yaw_body[2], body_val) end
      end
      if r.aa_yaw_body and r.aa_yaw_body[1] then
        pcall(ui.set, r.aa_yaw_body[1], body_mode)
      end
    end
    pcall(function()
      if r.aa_freestanding and r.aa_freestanding[1] then
        ui.set(r.aa_freestanding[1], freestanding_enabled)
        if r.aa_freestanding[2] then
          if freestanding_enabled then ui.set(r.aa_freestanding[2], "Always on") end
        end
      end
    end)
    Class.util.antiaim._last_applied["freestanding"] = freestanding_enabled
    local choke_now = 0
    pcall(function()
      choke_now = globals.chokedcommands and globals.chokedcommands() or 0
    end)
    if Class.util.antiaim._last_choke ~= nil then
      choke_now = Class.util.antiaim._last_choke
    end
    if choke_now == 0 or Class.util.antiaim._last_applied["freestanding_body"] == nil then
      pcall(function()
        if r.aa_fs_body_yaw then
          ui.set(r.aa_fs_body_yaw, body_freestanding_enabled)
        end
      end)
      Class.util.antiaim._last_applied["freestanding_body"] = body_freestanding_enabled
    end
  end
  -- Do not apply builder defaults to native Fake Lag controls.
  -- Preserve the user's current Amount, Variance, Limit and Enabled values;
  -- Hideshots Fix temporarily overrides only Limit when its condition is active.
  Class.util:hide_menu(false)
end
is_warmup_aa_active = function()
  local menu = Class.ui.menu.antiaim_tab.additional.extra
  local enabled = false
  pcall(function() enabled = menu.warmup.enabled:get() and true or false end)
  if not enabled then
    return false
  end
  local triggers = menu.warmup.triggers:get() or {}
  if #triggers == 0 then
    return false
  end

  local want_warmup, want_no_enemies = false, false
  for _, trigger in ipairs(triggers) do
    if trigger == "Warmup" then
      want_warmup = true
    elseif trigger == "No Enemies" then
      want_no_enemies = true
    end
  end

  if want_warmup then
    local rules = entity.get_game_rules()
    if rules and entity.get_prop(rules, "m_bWarmupPeriod") == 1 then
      return true
    end
  end

  if want_no_enemies then
    local local_player = entity.get_local_player()
    if local_player and entity.is_alive(local_player) then
      for index = 1, 64 do
        if index ~= local_player and entity.is_alive(index) and entity.is_enemy(index) then
          return false
        end
      end
      return true
    end
  end

  return false
end

-- Warmup AA is applied through apply_native_settings() using native AA controls.
-- Deliberately do not rewrite cmd.yaw or cmd.pitch here: doing so makes shots
-- follow the spinning command angles instead of the intended aimbot view angle.

function Class.util.antiaim.update_antiaim(cmd)
  Class.util.antiaim.manual_applied = false
  manual_direction()
  -- Flick is rendered through this builder pipeline; clear its per-tick flag up front so
  -- dead / legit-AA early returns below never leave a stale FLICK indicator.
  if Class.antiaim.flick_exploit then
    Class.antiaim.flick_exploit._active = false
  end
  if Class.antiaim.defensive_aa then
    Class.antiaim.defensive_aa._active = false
  end
  local local_player = entity.get_local_player()
  if not local_player or not entity.is_alive(local_player) then return end
  if Class.util.antiaim._force_reapply then
    Class.util.antiaim.reenable()
  end
  if cmd then
    Class.util.antiaim._last_choke = cmd.chokedcommands or 0
    Class.util.antiaim._holding_use = bit.band(cmd.buttons or 0, 32) ~= 0
  end
  Class.util.antiaim.current_team = entity.get_prop(local_player, "m_iTeamNum") == 2 and "T" or "CT"
  local current_condition = Class.util.antiaim.get_current_condition(cmd)
  local manual_requested = (tonumber(Class.util.antiaim.manual_direction) or 0) ~= 0
  local prefer_manual = prefer_manual_enabled()
  local use_freestanding = false
  if not manual_requested or not prefer_manual then
    pcall(function()
      use_freestanding = Class.ui.menu.antiaim_tab.additional.hotkey.freestanding:get()
    end)
    if use_freestanding then
      local disabled = Class.ui.menu.antiaim_tab.additional.hotkey.freestanding_disablers:get()
      if disabled then
        local current_condition_label = current_condition == "Air Crouch" and "Air Crouching"
          or current_condition == "Crouch" and "Crouching"
          or current_condition
        for _, st in ipairs(disabled) do
          if st == current_condition_label then
            use_freestanding = false
            break
          end
        end
      end
    end
  end
  Class.util.antiaim.freestanding_active = use_freestanding and true or false
  -- If both binds are active and Prefer Manual is off, suppress the Manual
  -- override entirely so Freestanding can own the final yaw for this tick.
  local use_manual = manual_requested and (prefer_manual or not use_freestanding)
  local freestanding_builder_mode = false
  if use_freestanding then
    local freestanding_index = 1
    for index, condition in ipairs(Class.util.antiaim.conditions) do
      if condition == "Freestanding" then
        freestanding_index = index
        break
      end
    end
    local freestanding_builder = (Class.util.antiaim.current_team == "CT")
      and Class.ui.antiaim_conditions_ct[freestanding_index]
      or Class.ui.antiaim_conditions_t[freestanding_index]
    local freestanding_override = false
    pcall(function()
      freestanding_override = freestanding_builder and freestanding_builder.override_state
        and freestanding_builder.override_state:get() and true or false
    end)
    if freestanding_override then
      current_condition = "Freestanding"
    else
      -- With the Freestanding override disabled, keep the active movement
      -- condition's own Builder profile. Do not fall back to Shared merely
      -- because the Freestanding profile itself has no override.
      freestanding_builder_mode = true
    end
  end
  local safe_head_active = false
  -- Do not let Safe Head steal the tick when a selected Manual bind is being
  -- deliberately yielded to an active Freestanding bind.
  if not manual_requested then
    pcall(function() safe_head_active = is_safe_head_active() and true or false end)
  end
  local condition_settings = (Class.util.antiaim.current_team == "CT") and Class.ui.antiaim_conditions_ct or Class.ui.antiaim_conditions_t
  local apply_team = Class.util.antiaim.current_team
  local function index_of(name)
    for index, condition in ipairs(Class.util.antiaim.conditions) do
      if condition == name then return index end
    end
    return 1
  end
  local function is_overridden(index)
    if index == 1 then return true end
    local st = condition_settings and condition_settings[index]
    if not st or not st.override_state then return false end
    local enabled = false
    pcall(function() enabled = st.override_state:get() and true or false end)
    return enabled
  end

  local legit_aa_index = index_of("Legit AA")
  local legit_aa_active = false
  if cmd and cmd.in_use == 1 then
    local legit_settings = condition_settings and condition_settings[legit_aa_index]
    if legit_settings and legit_settings.override_state then
      pcall(function()
        legit_aa_active = legit_settings.override_state:get() and true or false
      end)
    end
  end

  if legit_aa_active then
    local player = entity.get_local_player()
    local can_use_legit_aa = player ~= nil and entity.is_alive(player)
      and entity.get_prop(player, "m_bIsDefusing") ~= 1
      and entity.get_prop(player, "m_bIsGrabbingHostage") ~= 1

    if can_use_legit_aa then
      local in_bomb_site = entity.get_prop(player, "m_bInBombZone") == 1
      local is_weapon_bomb = false
      local weapon = entity.get_player_weapon(player)
      if weapon then
        is_weapon_bomb = (tonumber(entity.get_prop(weapon, "m_iItemDefinitionIndex")) or 0) == 49
      end
      local bomb_e_fix = false
      local ui_legit = condition_settings and condition_settings[legit_aa_index]
      if ui_legit and ui_legit.bomb_e_fix then
        pcall(function() bomb_e_fix = ui_legit.bomb_e_fix:get() and true or false end)
      end
      if in_bomb_site and (not bomb_e_fix or is_weapon_bomb) then
        can_use_legit_aa = false
      elseif (tonumber(entity.get_prop(player, "m_iTeamNum")) or 0) == 3 and (tonumber(cmd.pitch) or 0) > 15 then
        local ox, oy, oz = entity.get_origin(player)
        if ox then
          local bombs = entity.get_all("CPlantedC4")
          for bi = 1, bombs and #bombs or 0 do
            local bx, by, bz = entity.get_origin(bombs[bi])
            if bx then
              local dx, dy, dz = ox - bx, oy - by, oz - bz
              if (dx * dx + dy * dy + dz * dz) < 3844 then
                can_use_legit_aa = false
                break
              end
            end
          end
        end
      end
    end

    if can_use_legit_aa and Class.util.antiaim.has_use_target(player, cmd) then
      can_use_legit_aa = false  -- есть что использовать: отдаём E игре, AA не включаем
    end

    if can_use_legit_aa then
      if Class.util.antiaim._previous_condition_index ~= legit_aa_index
        or Class.util.antiaim._prev_team ~= apply_team then
        Class.util.antiaim._last_applied = {}
        Class.util.antiaim._delay_signature = nil
        Class.util.antiaim.delay_next = nil
        Class.util.antiaim.custom_delay_index = 1
        Class.util.antiaim.custom_delay_last = nil
        Class.util.antiaim._freeze_until_tick = 0
        Class.util.antiaim._last_freeze_tick = -1000000
        Class.util.antiaim.delay_last_tick = Class.util.antiaim.delay_counter or 0
      end
      Class.util.antiaim.current_condition_index = legit_aa_index
      Class.util.antiaim.current_condition = "Legit AA"
      Class.util.antiaim._previous_condition_index = legit_aa_index
      Class.util.antiaim._prev_team = apply_team

      Class.util.antiaim.load_builder_settings(cmd, legit_aa_index, apply_team)

      local legit_settings = Class.util.antiaim.current_settings
      legit_settings.pitch.mode = "Off"
      legit_settings.yaw.base = "Local view"
      if legit_settings.yaw.mode == "180" then
        legit_settings.yaw.value = normalize_yaw((tonumber(legit_settings.yaw.value) or 0) + 180)
      elseif legit_settings.yaw.mode == "L/R" then
        legit_settings.yaw.left_value = normalize_yaw((tonumber(legit_settings.yaw.left_value) or 0) + 180)
        legit_settings.yaw.right_value = normalize_yaw((tonumber(legit_settings.yaw.right_value) or 0) + 180)
      end
      legit_settings.freestanding.enabled = false

      Class.util.antiaim.apply_native_settings()
      cmd.in_use = 0
      return
    end
  end

  local index = index_of(current_condition)
  if not freestanding_builder_mode and not is_overridden(index) then
    index = 1
  end
  Class.util.antiaim.current_condition_index = index
  Class.util.antiaim.current_condition = Class.util.antiaim.conditions[index] or "Shared"
  local prev_idx = Class.util.antiaim._previous_condition_index
  local prev_team = Class.util.antiaim._prev_team
  if prev_idx ~= Class.util.antiaim.current_condition_index or prev_team ~= apply_team then
    Class.util.antiaim._last_applied = {}
    Class.util.antiaim._previous_condition_index = Class.util.antiaim.current_condition_index
    Class.util.antiaim._prev_team = apply_team
    Class.util.antiaim._delay_signature = nil
    Class.util.antiaim.delay_next = nil
    Class.util.antiaim.custom_delay_index = 1
    Class.util.antiaim.custom_delay_last = nil
    Class.util.antiaim._freeze_until_tick = 0
    Class.util.antiaim._last_freeze_tick = -1000000
    Class.util.antiaim.delay_last_tick = Class.util.antiaim.delay_counter or 0
  end
  Class.util.antiaim.load_builder_settings(cmd, Class.util.antiaim.current_condition_index, apply_team)
  if use_manual then
    apply_manual_settings()
  elseif safe_head_active then
    apply_safe_head()
  end
  Class.util.antiaim.manual_applied = use_manual and true or false
  do
    local aa = Class.util.antiaim
    local mem = Class.util.break_lc_mem
    local tickbase_control_enabled = false
    pcall(function()
      tickbase_control_enabled = Class.ui.menu.antiaim_tab.additional.fakelag.tickbase_enabled:get() and true or false
    end)
    if tickbase_control_enabled then
      local period = 14
      pcall(function()
        period = tonumber(Class.ui.menu.antiaim_tab.additional.fakelag.tickbase:get()) or 14
      end)
      period = math.max(1, math.min(22, math.floor(period + 0.5)))
      if mem and mem.set_limit then
        pcall(function() mem:set_limit(period) end)
      end
    elseif mem and mem.restore then
      pcall(function() mem:restore() end)
    end
    if aa.current_settings.break_lc and cmd then
      pcall(function() cmd.force_defensive = true end)
    end

  end
  apply_freestanding(is_freestanding_active())
  if is_avoid_backstab_active() and not use_manual and not is_freestanding_active() then
    apply_avoid_backstab()
  end
  if is_fast_ladder_active() then
    apply_fast_ladder(cmd)
  end
  update_fast_ladder_avoid(cmd)
  local is_manual = use_manual
  if is_manual then
    local la = Class.util.antiaim._last_applied
    if la then
      la["yaw_mode"] = nil
      la["yaw_val"] = nil
      la["yaw_base"] = nil
      la["body_mode"] = nil
      la["body_val"] = nil
    end
  elseif Class.util.antiaim._was_manual then
    Class.util.antiaim._last_applied = {}
  end
  Class.util.antiaim._was_manual = is_manual
  -- Defensive AA overrides current_settings during an active exploit; its existing
  -- manual guard remains tied to the selected Manual direction. Flick owns pitch only.
  if Class.antiaim.defensive_aa then Class.antiaim.defensive_aa:handle(cmd) end
  if Class.antiaim.flick_exploit then Class.antiaim.flick_exploit:handle(cmd) end
  Class.util.antiaim.apply_native_settings()
  Class.util.antiaim._force_reapply = false
end


-- Preserve the debug overlay created earlier; this table rebuild must not discard it.
Class.visuals = {
 watermark_ui = {
  alpha = 0,
  pos = { x = nil, y = nil },
  target_pos = { x = nil, y = nil },
  dragging = false,
  drag_offset = { x = 0, y = 0 },
  setup = function(self)
    local screen_width, screen_height = client.screen_size()
    local x, y = Class.util.window_pos:get("wm_x", "wm_y", screen_width * 0.57, screen_height * 0.76)
    self.pos.x, self.pos.y = x, y
    self.target_pos.x, self.target_pos.y = x, y
  end,
  save_pos = function(self)
    Class.util.window_pos:set("wm_x", "wm_y", self.target_pos.x, self.target_pos.y)
  end,
  handle_drag = function(self, bx, by, bw, bh)
    if not ui.is_menu_open() then
      if self.dragging then
        self.dragging = false
        self:save_pos()
      end
      return
    end
    local mouse_x, mouse_y = ui.mouse_position()
    local down = client.key_state(0x01)
    local hovered = mouse_x >= bx and mouse_x <= bx + bw and mouse_y >= by and mouse_y <= by + bh
    if down and not self.dragging and hovered then
      self.dragging = true
      self.drag_offset.x = mouse_x - self.target_pos.x
      self.drag_offset.y = mouse_y - self.target_pos.y
    end
    if self.dragging then
      if down then
        local screen_width, screen_height = client.screen_size()
        local nx = Class.util.clamp(mouse_x - self.drag_offset.x, 0, screen_width - bw)
        local ny = Class.util.clamp(mouse_y - self.drag_offset.y, 0, screen_height - bh)
        nx, ny = Class.util.snap_drag:apply(nx, ny, bw, bh)
        self.target_pos.x, self.target_pos.y = nx, ny
      else
        self.dragging = false
        self:save_pos()
      end
    end
  end,
  _utf8_chars = function(self, str)
    str = tostring(str or "")
    local chars = {}
    local index = 1
    local n = #str
    while index <= n do
      local c = str:byte(index)
      local length = 1
      if not c then break end
      if c >= 0xF0 then length = 4
      elseif c >= 0xE0 then length = 3
      elseif c >= 0xC0 then length = 2
      end
      if index + length - 1 > n then length = 1 end
      chars[#chars + 1] = str:sub(index, index + length - 1)
      index = index + length
    end
    return chars
  end,
  _is_encodable_char = function(self, ch)
    if not ch or ch == "" or ch == " " or ch == "\t" then return false end
    local b = ch:byte(1)
    if not b then return false end
    if (b >= 65 and b <= 90) or (b >= 97 and b <= 122) or (b >= 48 and b <= 57) then
      return true
    end
    if b >= 128 then return true end
    return false
  end,
  _fx_draw_text = function(self, x, y, r, g, b, a, font_name, text)
    if not text or text == "" then return 0 end
    local w = select(1, renderer.measure_text(font_name, text)) or 0
    renderer.text(x, y, r, g, b, a, font_name, nil, text)
    return w
  end,
    render = function(self)
      local watermark_ui = Class.ui.menu.visuals_tab.other.watermark
      local frames = 8 * globals.frametime()
      self.alpha = math.min(1, self.alpha + frames)
      if self.alpha < 0.01 then return end
      local font_mapping = self._font_mapping
      if not font_mapping then
        font_mapping = { ["Default"] = "", ["Pixel"] = "-", ["Bold"] = "b" }
        self._font_mapping = font_mapping
      end
     local font_name = font_mapping[watermark_ui.font:get()] or ""
     local screen_width = client.screen_size()
     local raw_watermark_text = tostring(watermark_ui.text:get() or "")
     local input_text = raw_watermark_text:gsub("^%s+", ""):gsub("%s+$", "")
     local watermark_segments, plain_parts = {}, {}
     local has_watermark_icons = false
     local known_watermark_icons = self._known_watermark_icons
     if not known_watermark_icons then
       known_watermark_icons = {
       sparkles=true, star=true, check=true, shield=true, bolt=true, heart=true,
       code=true, globe=true, ["shield-check"]=true, ["check-circle"]=true,
       ["x-mark"]=true, ["plus"]=true, ["minus"]=true, ["chevron-right"]=true,
       ["chevron-left"]=true, ["arrow-right"]=true, ["arrow-left"]=true,
       ["arrow-up"]=true, ["arrow-down"]=true, fire=true, sun=true, moon=true,
       eye=true, ["eye-slash"]=true, home=true, user=true, users=true,
       bell=true, cog=true, settings=true, wrench=true, lock=true, unlock=true,
       key=true, link=true, ["paper-airplane"]=true, chat=true, ["chat-bubble-left"]=true,
       envelope=true, phone=true, ["magnifying-glass"]=true, search=true,
       clock=true, calendar=true, map=true, pin=true, ["map-pin"]=true,
       flag=true, trophy=true, gift=true, crown=true, rocket=true,
       lightning=true, wifi=true, signal=true, battery=true, cpu=true,
       monitor=true, computer=true, server=true, cloud=true, download=true,
       upload=true, trash=true, pencil=true, ["document-text"]=true,
       ["clipboard-document"]=true, ["shopping-cart"]=true, ["credit-card"]=true,
       ["chart-bar"]=true, ["chart-pie"]=true, ["arrow-path"]=true,
       ["hand-thumb-up"]=true, ["hand-thumb-down"]=true, ["face-smile"]=true,
       ["exclamation-triangle"]=true, ["information-circle"]=true,
       ["question-mark-circle"]=true, ["ellipsis-horizontal"]=true,
       ["ellipsis-vertical"]=true, ["bars-3"]=true, ["play"]=true, ["pause"]=true,
       ["stop"]=true, ["forward"]=true, ["backward"]=true, ["musical-note"]=true,
       ["photo"]=true, ["video-camera"]=true, ["microphone"]=true, ["speaker-wave"]=true,
       ["command-line"]=true, terminal=true, bug=true, puzzle=true, cube=true,
       diamond=true, building=true, academic=true, ["academic-cap"]=true,
       ["clipboard-check"]=true, ["check-badge"]=true, ["document-check"]=true
       }
       self._known_watermark_icons = known_watermark_icons
     end
     local marker_names = self._watermark_marker_names
     if not marker_names then
       marker_names = {pre=true, m=true, post=true, icon=true, icon_pre=true, icon_post=true}
       self._watermark_marker_names = marker_names
     end
     local function append_text(value, role)
       if value and value ~= "" then
         if watermark_ui.font:get() == "Pixel" then value = value:upper() end
         watermark_segments[#watermark_segments + 1] = {kind = "text", text = value, role = role or "main"}
         plain_parts[#plain_parts + 1] = value
       end
     end
     local function append_icon(value, role)
       local name = tostring(value or ""):lower():gsub("^%s+", ""):gsub("%s+$", ""):gsub("_", "-")
       if name == "moon-stars" then name = "moon" end
       if name ~= "" then
         if known_watermark_icons[name] then
           watermark_segments[#watermark_segments + 1] = {kind = "icon", name = name, role = role or "main"}
           has_watermark_icons = true
         else
           append_text(tostring(value or ""), role or "main")
         end
       end
     end
     local commands = {}
     local search_at = 1
     while search_at <= #input_text do
       local marker_start, marker_end, marker_name = input_text:find("([%a_]+)=", search_at)
       if not marker_start then break end
       if marker_names[marker_name] then
         commands[#commands + 1] = {name = marker_name, start = marker_start, value_start = marker_end + 1}
       end
       search_at = marker_end + 1
     end
     if #commands > 0 then
       local parts = {}
       for index = 1, #commands do
         local marker = commands[index]
         local next_marker = commands[index + 1]
         local value = input_text:sub(marker.value_start, next_marker and (next_marker.start - 1) or #input_text)
         value = value:gsub("%s+$", "")
         if marker.name == "icon" or marker.name == "icon_pre" or marker.name == "icon_post" then
           value = value:gsub("^%s+", "")
         end
         parts[marker.name] = value
       end
       if parts.icon_pre and parts.icon_pre ~= "" then
         append_icon(parts.icon_pre, "prefix")
         append_text(" ", "prefix")
       end
       append_text(parts.pre, "prefix")
       if parts.icon and parts.icon ~= "" then
         append_icon(parts.icon, "main")
         if parts.m and parts.m ~= "" then append_text(" ", "main") end
       end
       append_text(parts.m, "main")
       append_text(parts.post, "postfix")
       if parts.icon_post and parts.icon_post ~= "" then
         append_text(" ", "postfix")
         append_icon(parts.icon_post, "postfix")
       end
     else
       local scan_pos = 1
       while scan_pos <= #input_text do
         local word_start, word_end = input_text:find("%S+", scan_pos)
         if not word_start then
           append_text(input_text:sub(scan_pos), "main")
           break
         end
         if word_start > scan_pos then append_text(input_text:sub(scan_pos, word_start - 1), "main") end
         local word = input_text:sub(word_start, word_end)
         local normalized = word:lower():gsub("_", "-")
         if known_watermark_icons[normalized] then
           append_icon(normalized, "main")
         else
           append_text(word, "main")
         end
         scan_pos = word_end + 1
       end
     end
     local watermark_text = table.concat(plain_parts)
     local rt = globals.realtime()
     local cache = self._render_cache
     if not cache or (rt - (cache.t or 0)) >= 0.10 then
       cache = cache or {}
       cache.t = rt
       cache.color_mode = watermark_ui.color_mode:get()
       cache.effect = watermark_ui.effect:get()
       self._render_cache = cache
     end
     local color_mode = cache.color_mode or "Default"
     local effect = cache.effect or "Disabled"
     local text_direction = "Right"
     if color_mode == "Gradient" then
       text_direction = watermark_ui.gradient.direction:get() or "Right"
     elseif color_mode == "Rainbow" then
       text_direction = watermark_ui.rainbow.direction:get() or "Right"
     end
     if watermark_text == "" and not has_watermark_icons then
       self.alpha = 0
       return
     end
     local pulse_alpha = 255
     if effect == "Pulse" then
       local pulse_speed = watermark_ui.pulse_speed:get()
       local pulse = math.sin(rt * (pulse_speed / 10)) * 0.5 + 0.5
       pulse_alpha = math.floor(255 * pulse)
     end
     local function wa(a)
       a = a or 255
       return math.max(0, math.min(255, math.floor(a * (pulse_alpha / 255))))
     end
     local function effect_text(text)
       if effect ~= "Encoded" or not text or text == "" then return text or "" end
       local phase = rt % 3
       if phase >= 1 then return text end
       local wave = math.sin(rt * math.pi) * 0.5 + 0.5
       local chars = self:_utf8_chars(text)
       local symbols = {"!", "@", "#", "$", "%", "^", "&", "+", "="}
       local output = {}
       for index = 1, #chars do
         local ch = chars[index]
         if self:_is_encodable_char(ch) and math.random() < 0.8 and wave > math.random() then
           output[#output + 1] = symbols[math.random(#symbols)]
         else
         output[#output + 1] = ch
       end
     end
     return table.concat(output)
   end
   local measure_plain = watermark_text
   local measured_text_height = select(2, renderer.measure_text(font_name, measure_plain ~= "" and measure_plain or "Ag")) or 10
   measured_text_height = math.max(8, math.min(24, tonumber(measured_text_height) or 10))
   local icon_size = math.max(10, math.min(18, measured_text_height + 1))
   local total_units, main_units, watermark_width = 0, 0, 0
   for _, segment in ipairs(watermark_segments) do
     if segment.kind == "text" then
       segment.display_text = effect_text(segment.text)
       segment.char_count = #self:_utf8_chars(segment.display_text)
       segment.unit_start = total_units
       if segment.role ~= "prefix" and segment.role ~= "postfix" then
         segment.main_unit_start = main_units
         main_units = main_units + segment.char_count
       end
       segment.width = select(1, renderer.measure_text(font_name, segment.display_text)) or 0
       total_units = total_units + segment.char_count
       watermark_width = watermark_width + segment.width
     else
       segment.unit_start = total_units
       if segment.role ~= "prefix" and segment.role ~= "postfix" then
         segment.main_unit_start = main_units
         main_units = main_units + 1
       end
       segment.width = icon_size + 2
       total_units = total_units + 1
       watermark_width = watermark_width + segment.width
     end
   end
   local function hsv_rgb(hue, saturation, value)
     hue = (hue % 1) * 6
     saturation = math.max(0, math.min(1, saturation))
     value = math.max(0, math.min(1, value))
     local chroma = value * saturation
     local x = chroma * (1 - math.abs((hue % 2) - 1))
     local m = value - chroma
     local r, g, b
     if hue < 1 then r, g, b = chroma, x, 0
     elseif hue < 2 then r, g, b = x, chroma, 0
     elseif hue < 3 then r, g, b = 0, chroma, x
     elseif hue < 4 then r, g, b = 0, x, chroma
     elseif hue < 5 then r, g, b = x, 0, chroma
     else r, g, b = chroma, 0, x end
     return math.floor((r + m) * 255 + 0.5), math.floor((g + m) * 255 + 0.5), math.floor((b + m) * 255 + 0.5), 255
   end
   local function gradient_color_at(unit_index)
     local inner = {watermark_ui.gradient.color.inner:get()}
     local outer = {watermark_ui.gradient.color.outer:get()}
     local direction = watermark_ui.gradient.direction:get() or "Right"
     local denominator = math.max(main_units - 1, 1)
     local progress = unit_index / denominator
     local speed = (tonumber(watermark_ui.gradient.speed:get()) or 10) / 10
     local phase = progress + globals.curtime() * speed * (direction == "Right" and -1 or 1)
     local amount = math.abs(math.cos(phase))
     local r = (inner[1] or 255) + ((outer[1] or 255) - (inner[1] or 255)) * amount
     local g = (inner[2] or 255) + ((outer[2] or 255) - (inner[2] or 255)) * amount
     local b = (inner[3] or 255) + ((outer[3] or 255) - (inner[3] or 255)) * amount
     local a = (inner[4] or 255) + ((outer[4] or 255) - (inner[4] or 255)) * amount
     return math.floor(r + 0.5), math.floor(g + 0.5), math.floor(b + 0.5), math.floor(a + 0.5)
   end
   local function rainbow_color_at(unit_index)
     local denominator = math.max(main_units - 1, 1)
     local direction = watermark_ui.rainbow.direction:get() or "Right"
     local sign = direction == "Left" and -1 or 1
     local speed = (tonumber(watermark_ui.rainbow.speed:get()) or 10) / 10
     local hue = (unit_index / denominator + globals.realtime() * speed * 0.22 * sign) % 1
     local saturation = (tonumber(watermark_ui.rainbow.saturation:get()) or 100) / 100
     return hsv_rgb(hue, saturation, 1)
   end
   local function icon_color_at(unit_index, role)
     if role == "prefix" then
       local c = {watermark_ui.gradient.color.prefix:get()}
       return c[1] or 255, c[2] or 255, c[3] or 255, c[4] or 255
     elseif role == "postfix" then
       local c = {watermark_ui.gradient.color.postfix:get()}
       return c[1] or 255, c[2] or 255, c[3] or 255, c[4] or 255
     elseif color_mode == "Default" then
       local c = {watermark_ui.default.color:get()}
       return c[1] or 255, c[2] or 255, c[3] or 255, c[4] or 255
     elseif color_mode == "Rainbow" then
       return rainbow_color_at(unit_index)
     end
     return gradient_color_at(unit_index)
   end
   local w, h = watermark_width + 4, math.max(16, measured_text_height)
   local screen_width, screen_height = client.screen_size()
   if not self.pos.x then
     local x, y = Class.util.window_pos:get("wm_x", "wm_y", screen_width * 0.57, screen_height * 0.76)
     self.pos.x, self.pos.y = x, y
     self.target_pos.x, self.target_pos.y = x, y
   end
   self.pos.x = Class.motion.window(self.pos.x, self.target_pos.x, 0.32)
   self.pos.y = Class.motion.window(self.pos.y, self.target_pos.y, 0.32)
   local x, y = self.pos.x, self.pos.y
   if ui.is_menu_open() then
     self:handle_drag(x, y, w, h)
   end
   local cursor_x = x
   local default_color = {watermark_ui.default.color:get()}
   local prefix_color = {watermark_ui.gradient.color.prefix:get()}
   local postfix_color = {watermark_ui.gradient.color.postfix:get()}
   local function solid_color(role)
     if role == "prefix" then return prefix_color end
     if role == "postfix" then return postfix_color end
     return default_color
   end
   local function animate_main(role)
     return role ~= "prefix" and role ~= "postfix"
   end
   for _, segment in ipairs(watermark_segments) do
     if segment.kind == "text" then
       local draw_text = segment.display_text or ""
       if draw_text ~= "" then
         if animate_main(segment.role) and color_mode == "Gradient" then
           local inner = {watermark_ui.gradient.color.inner:get()}
           local outer = {watermark_ui.gradient.color.outer:get()}
           local gradient_text = Class.render.gradient_text(
             draw_text, (tonumber(watermark_ui.gradient.speed:get()) or 10) / 10, text_direction,
             inner[1], inner[2], inner[3], wa(inner[4] or 255),
             outer[1], outer[2], outer[3], wa(outer[4] or 255),
             segment.main_unit_start or 0, main_units
           )
           renderer.text(math.floor(cursor_x + 0.5), y, 255, 255, 255, wa(255), font_name, nil, gradient_text)
         elseif animate_main(segment.role) and color_mode == "Rainbow" then
           local rainbow_text = Class.render.rainbow_text(
             draw_text, (tonumber(watermark_ui.rainbow.speed:get()) or 10) / 10, text_direction,
             wa(255), (tonumber(watermark_ui.rainbow.saturation:get()) or 100) / 100,
             segment.main_unit_start or 0, main_units
           )
           renderer.text(math.floor(cursor_x + 0.5), y, 255, 255, 255, wa(255), font_name, nil, rainbow_text)
         else
           local color = solid_color(segment.role)
           self:_fx_draw_text(
             math.floor(cursor_x + 0.5), y,
             color[1] or 255, color[2] or 255, color[3] or 255,
             wa(color[4] or 255), font_name, draw_text
           )
         end
       end
       cursor_x = cursor_x + (segment.width or 0)
     else
       local icon_key = segment.name .. "_outline"
       self._watermark_icons = self._watermark_icons or {}
       self._watermark_icon_requested = self._watermark_icon_requested or {}
       local icon_texture = self._watermark_icons[icon_key]
       if icon_texture == nil and not self._watermark_icon_requested[icon_key] then
         self._watermark_icon_requested[icon_key] = true
         icons_lib.hero.get_texture(segment.name, "outline", {255, 255, 255, 255}, icon_size, function(tex)
           if tex then self._watermark_icons[icon_key] = tex end
         end)
       end
       icon_texture = self._watermark_icons[icon_key]
       if icon_texture then
         local color
         local cr, cg, cb, ca = icon_color_at(segment.main_unit_start or segment.unit_start, segment.role)
         color = {cr, cg, cb, ca}
         local icon_y = y + math.floor((measured_text_height - icon_size) / 2 + 0.5)
         renderer.texture(icon_texture, math.floor(cursor_x + 0.5), math.floor(icon_y + 0.5), icon_size, icon_size,
           color[1] or 255, color[2] or 255, color[3] or 255, wa(color[4] or 255))
       end
       cursor_x = cursor_x + segment.width
     end
   end
 end
},
velocity_indicator = {
 bar_w = 180,
 bar_h = 8,
 fill_h = 4,
 corner_r = 4,
 pos = { x = nil, y = nil },
 target_pos = { x = nil, y = nil },
 dragging = false,
 drag_offset = { x = 0, y = 0 },
 mouse_was_down = false,
 display_mod = 1,
 setup = function(self)
   local screen_width, screen_height = client.screen_size()
   local x, y = Class.util.window_pos:get("slow_x", "slow_y", screen_width / 2 - 90, screen_height * 0.35)
   self.pos.x, self.pos.y = x, y
   self.target_pos.x, self.target_pos.y = x, y
 end,
 save_pos = function(self)
   Class.util.window_pos:set("slow_x", "slow_y", self.target_pos.x, self.target_pos.y)
 end,
 handle_drag = function(self, bx, by, bw, bh)
   if not ui.is_menu_open() then
     self.dragging = false
     self.mouse_was_down = client.key_state(0x01)
     return
   end
   local mouse_x, mouse_y = ui.mouse_position()
   local mouse_down = client.key_state(0x01)
   local hovered = mouse_x >= bx - 10 and mouse_x <= bx + bw + 10
   and mouse_y >= by - 18 and mouse_y <= by + bh + 6
   if mouse_down and not self.mouse_was_down and hovered then
     self.dragging = true
     self.drag_offset.x = mouse_x - self.target_pos.x
     self.drag_offset.y = mouse_y - self.target_pos.y
   end
   if self.dragging then
     if mouse_down then
       local screen_width, screen_height = client.screen_size()
       local nx = Class.util.clamp(mouse_x - self.drag_offset.x, 20, screen_width - self.bar_w - 20)
       local ny = Class.util.clamp(mouse_y - self.drag_offset.y, 20, screen_height - 40)
       nx, ny = Class.util.snap_drag:apply(nx, ny, self.bar_w or bw or 180, bh or 12)
       self.target_pos.x, self.target_pos.y = nx, ny
     else
     self.dragging = false
     self:save_pos()
   end
 end
 self.mouse_was_down = mouse_down
 end,
 _round = function(self, x, y, w, h, radius, r, g, b, a)
   if a < 1 or w < 1 or h < 1 then return end
   x, y, w, h = math.floor(x), math.floor(y), math.floor(w), math.floor(h)
   radius = math.floor(math.min(radius or 5, w / 2, h / 2))
   if radius < 1 then
     renderer.rectangle(x, y, w, h, r, g, b, a)
     return
   end
   renderer.rectangle(x + radius, y, w - radius * 2, h, r, g, b, a)
   renderer.rectangle(x, y + radius, radius, h - radius * 2, r, g, b, a)
   renderer.rectangle(x + w - radius, y + radius, radius, h - radius * 2, r, g, b, a)
   renderer.circle(x + radius, y + radius, r, g, b, a, radius, 180, 0.25)
   renderer.circle(x + w - radius, y + radius, r, g, b, a, radius, 90, 0.25)
   renderer.circle(x + radius, y + h - radius, r, g, b, a, radius, 270, 0.25)
   renderer.circle(x + w - radius, y + h - radius, r, g, b, a, radius, 0, 0.25)
 end,
 _shadow = function(self, x, y, w, h, radius, base_a)
   local a1 = math.floor((base_a or 255) * 0.28)
   local a2 = math.floor((base_a or 255) * 0.12)
   if a1 > 0 then self:_round(x + 2, y + 3, w, h, radius, 0, 0, 0, a1) end
   if a2 > 0 then self:_round(x + 4, y + 6, w, h, radius + 1, 0, 0, 0, a2) end
 end,
 render = function(self)
   local visuals_item = Class.ui.menu.visuals_tab.interface.velocity_indicator
   if not visuals_item.enabled:get() then return end
   local menu_open = ui.is_menu_open()
   local local_player = entity.get_local_player()
   local velocity_modifier
   if menu_open then
     velocity_modifier = (math.sin(globals.realtime() * 0.7) + 1) * 0.5
   elseif local_player and entity.is_alive(local_player) then
     velocity_modifier = entity.get_prop(local_player, "m_flVelocityModifier") or 1
     if velocity_modifier >= 0.999 then return end
   else
   return
 end
 local screen_w, screen_h = client.screen_size()
 if not self.pos.x then
   self.pos.x = screen_w * 0.5 - self.bar_w * 0.5
   self.pos.y = screen_h * 0.22
   self.target_pos.x = self.pos.x
   self.target_pos.y = self.pos.y
 end
 self.pos.x = Class.motion.window(self.pos.x, self.target_pos.x, 0.32)
 self.pos.y = Class.motion.window(self.pos.y, self.target_pos.y, 0.32)
 local bar_x, bar_y = self.pos.x, self.pos.y
 local bar_w, bar_h = self.bar_w, self.bar_h
 self:handle_drag(bar_x, bar_y, bar_w, bar_h)
 self.display_mod = Class.motion.exponential_smooth(self.display_mod, velocity_modifier, 0.18)
 local fade_a = 1
 if not menu_open and self.display_mod > 0.9 then
   fade_a = (1 - self.display_mod) / 0.1
   if fade_a < 0.02 then return end
 end
 local r, g, b, a = visuals_item.color:get()
 local final_a = math.floor((a or 255) * fade_a)
 local bg_a = math.floor(105 * fade_a)
 if final_a < 1 then return end
 local rad = self.corner_r or 5
 local fill_h = self.fill_h
 local pad = 3
 local fill_y = bar_y + (bar_h - fill_h) * 0.5
 local fill_w = math.max(0, (bar_w - pad * 2) * self.display_mod)
 local fill_x = bar_x + pad
 self:_shadow(bar_x, bar_y, bar_w, bar_h, rad, bg_a)
 self:_round(bar_x, bar_y, bar_w, bar_h, rad, 8, 8, 11, bg_a)
 if fill_w > 1 then
   local fr = math.min(rad - 1, math.floor(fill_h / 2))
   if fr < 1 then fr = 1 end
   local fg = math.floor(final_a * 0.20)
   if fg > 0 then
     self:_round(fill_x - 2, fill_y - 2, fill_w + 4, fill_h + 4, fr + 1, r, g, b, fg)
   end

   renderer.gradient(
     fill_x, fill_y, fill_w, fill_h,
     0, 0, 0, final_a,
     r, g, b, final_a,
     true
   )

   if fill_w >= fr * 2 then
     renderer.circle(fill_x + fr, fill_y + fr, 0, 0, 0, final_a, fr, 180, 0.25)
     renderer.circle(fill_x + fill_w - fr, fill_y + fr, r, g, b, final_a, fr, 0, 0.25)
   end
 end
 renderer.text(
 math.floor(bar_x + bar_w * 0.5),
 math.floor(bar_y - 12),
 255, 255, 255, final_a,
 "c", 0,
 string.format("Max velocity reduced by %.0f%%", (1 - self.display_mod) * 100)
 )
 end
},
custom_scope = {
 alpha = 0,
 original_overlay_state = nil,
 _overlay_active = false,
 interpolated_values = { length = 0, gap = 0 },
 overlay_handler = {
  set_true = function()
    local reference = Class.util.reference.visuals_scope_overlay
    if reference then ui.set(reference, true) end
  end,
  set_false = function()
    local reference = Class.util.reference.visuals_scope_overlay
    if reference then ui.set(reference, false) end
  end
 },
reset = function(self)
  self.alpha = 0
  self.interpolated_values.length = 0
  self.interpolated_values.gap = 0
  self._overlay_active = false
end,
_update_overlay = function(self)
  local visuals_item = Class.ui.menu.visuals_tab.interface.custom_scope
  local reference = Class.util.reference.visuals_scope_overlay
  if not reference or not visuals_item then return end
  local want = false
  pcall(function() want = visuals_item.enabled:get() and true or false end)
  if want == self._overlay_active then return end
  self._overlay_active = want
  if want then
    if self.original_overlay_state == nil then
      self.original_overlay_state = ui.get(reference)
    end
    client.set_event_callback("paint", self.overlay_handler.set_false)
    client.set_event_callback("paint_ui", self.overlay_handler.set_true)
  else
  self.alpha = 0
  pcall(function()
    client.unset_event_callback("paint", self.overlay_handler.set_false)
    client.unset_event_callback("paint_ui", self.overlay_handler.set_true)
  end)
  if self.original_overlay_state ~= nil then
    ui.set(reference, self.original_overlay_state)
    self.original_overlay_state = nil
  end
end
end,
_rot = function(self, x, y, deg)
  local rad = math.rad(deg)
  local c, s = math.cos(rad), math.sin(rad)
  return x * c - y * s, x * s + y * c
end,
_arm = function(self, center_x, center_y, ox1, oy1, ox2, oy2, r, g, b, a)
  local dx, dy = ox2 - ox1, oy2 - oy1
  if math.abs(dy) < 0.5 then
    local x1 = math.floor(center_x + math.min(ox1, ox2) + 0.5)
    local x2 = math.floor(center_x + math.max(ox1, ox2) + 0.5)
    local y  = math.floor(center_y + oy1 + 0.5)
    local w = x2 - x1
    if w < 1 then return end
    if ox1 < ox2 then
      renderer.gradient(x1, y, w, 1, r, g, b, 0, r, g, b, a, true)
    else
    renderer.gradient(x1, y, w, 1, r, g, b, a, r, g, b, 0, true)
  end
elseif math.abs(dx) < 0.5 then
  local y1 = math.floor(center_y + math.min(oy1, oy2) + 0.5)
  local y2 = math.floor(center_y + math.max(oy1, oy2) + 0.5)
  local x  = math.floor(center_x + ox1 + 0.5)
  local h = y2 - y1
  if h < 1 then return end
  if oy1 < oy2 then
    renderer.gradient(x, y1, 1, h, r, g, b, 0, r, g, b, a, false)
  else
  renderer.gradient(x, y1, 1, h, r, g, b, a, r, g, b, 0, false)
end
else
local steps = 8
for index = 0, steps - 1 do
  local t0 = index / steps
  local t1 = (index + 1) / steps
  local xa = center_x + ox1 + dx * t0
  local ya = center_y + oy1 + dy * t0
  local xb = center_x + ox1 + dx * t1
  local yb = center_y + oy1 + dy * t1
  local aa = math.floor(a * ((t0 + t1) * 0.5))
  renderer.line(xa, ya, xb, yb, r, g, b, aa)
  renderer.line(xa + 0.5, ya, xb + 0.5, yb, r, g, b, aa)
end
end
end,
render = function(self)
  local element = Class.ui.menu.visuals_tab.interface.custom_scope
  if not element then return end
  self:_update_overlay()
  if not element.enabled:get() then return end
  local local_player = entity.get_local_player()
  if not local_player then return end
  local screen_width, screen_height = client.screen_size()
  local scale = screen_height / 1080
  local length_raw = element.offset.length:get()
  local gap_raw = element.offset.gap:get()
  self.interpolated_values.length = Class.motion.interpolation(self.interpolated_values.length, length_raw, 0.075)
  self.interpolated_values.gap = Class.motion.interpolation(self.interpolated_values.gap, gap_raw, 0.075)
  local length = self.interpolated_values.length * scale
  local gap = self.interpolated_values.gap * scale
  if length < gap + 4 then length = gap + 4 end
  local color = { element.color:get() }
  local r, g, b, a = color[1], color[2], color[3], color[4] or 191
  if type(r) == "table" then
    a = r[4] or r.a or 191
    b = r[3] or r.b or 255
    g = r[2] or r.g or 255
    r = r[1] or r.r or 255
  end
  local wpn = entity.get_player_weapon(local_player)
  local scope_level = wpn and entity.get_prop(wpn, "m_zoomLevel") or nil
  local scoped = entity.get_prop(local_player, "m_bIsScoped") == 1
  local resume_zoom = entity.get_prop(local_player, "m_bResumeZoom") == 1
  local is_valid = entity.is_alive(local_player) and wpn ~= nil and scope_level ~= nil
  local act = is_valid and scope_level > 0 and scoped and not resume_zoom
  local appear_frames = 8
  pcall(function() appear_frames = tonumber(element.appear_speed:get()) or 8 end)
  appear_frames = math.max(1, math.min(24, math.floor(appear_frames)))
  local step = 1 / appear_frames
  self.alpha = Class.util.clamp(self.alpha + (act and step or -step), 0, 1)
  if self.alpha < 0.01 then return end
  local alpha = math.floor(self.alpha * a)
  local offset_x = math.floor(screen_width * 0.5)
  local offset_y = math.floor(screen_height * 0.5)
  local gap_i = math.max(0, math.floor(gap + 0.5))
  local len_i = math.max(gap_i + 4, math.floor(length + 0.5))
  local mode = element.mode:get()
  local animate = false
  pcall(function() animate = element.animate and element.animate:get() and true or false end)
  local arms = {
   { 0, -len_i, 0, -gap_i },
   { 0,  len_i, 0,  gap_i },
   {-len_i, 0, -gap_i, 0 },
   { len_i, 0,  gap_i, 0 },
  }
  local reversed = false
  pcall(function() reversed = element.reversed and element.reversed:get() and true or false end)
  -- Reverse line direction (gradient runs the other way): swap arm endpoints.
  if reversed then
    for index = 1, 4 do
      local a = arms[index]
      arms[index] = { a[3], a[4], a[1], a[2] }
    end
  end
  if mode == "Rotated" then
    local base = 45
    if animate then
      local vx, vy = entity.get_prop(local_player, "m_vecVelocity")
      local speed = 0
      if vx and vy then speed = math.sqrt(vx * vx + vy * vy) end
      if speed >= 5 then
        base = (globals.curtime() * 180) % 360
      end
    end
    for index = 1, 4 do
      local x1, y1 = self:_rot(arms[index][1], arms[index][2], base)
      local x2, y2 = self:_rot(arms[index][3], arms[index][4], base)
      arms[index] = { x1, y1, x2, y2 }
    end
  end
  for index = 1, 4 do
    self:_arm(offset_x, offset_y, arms[index][1], arms[index][2], arms[index][3], arms[index][4], r, g, b, alpha)
  end
end,
shutdown = function(self)
  pcall(function()
    client.unset_event_callback("paint", self.overlay_handler.set_false)
    client.unset_event_callback("paint_ui", self.overlay_handler.set_true)
  end)
  local reference = Class.util.reference.visuals_scope_overlay
  if reference and self.original_overlay_state ~= nil then
    ui.set(reference, self.original_overlay_state)
    self.original_overlay_state = nil
  end
  self:reset()
end
},
manual_arrows = {
 _ease = function(self, current, target, rate)
   local dt = math.max(0, math.min(0.1, globals.frametime()))
   return current + (target - current) * (1 - math.exp(-rate * dt))
 end,
 _reset_styles = function(self)
   self.dot, self.pointers = nil, nil
 end,
 _glow_dot = function(self, x, y, color, alpha, scale)
   local core = math.max(1, math.floor(2 * scale + 0.5))
   local extent = math.floor(22 * scale + 0.5)
   for i = 7, 1, -1 do
     local t = i / 10
     renderer.circle(x, y, math.floor(color[1]), math.floor(color[2]), math.floor(color[3]),
       math.floor(alpha * 0.44 * (1 - t)^1.15), core + math.floor(extent * t + 0.5), 0, 1)
   end
 end,
 _render_cs2 = function(self, menu_item, cx, cy, offset, dir, color)
   local _, height = renderer.measure_text("d", "a")
   local scale = math.max(1, (height or 12) / 12)
   -- Source Glow dot uses 78px. The existing Arrow Offset slider remains usable.
   local distance = math.floor(offset * (78 / 42) * scale + 0.5)
   cx, cy = cx + 1, cy + 1
   local x, y = cx, cy + distance
   local idle = {menu_item.cs2_idle_color:get()}
   local target = dir == 0 and idle or color
   if dir == 1 then x, y = cx - distance, cy
   elseif dir == 2 then x, y = cx + distance, cy
   elseif dir == 3 then x, y = cx, cy - distance end
   local now = globals.realtime()
   local state = self.dot
   if not state then
     state = {x = x, y = y, color = {target[1], target[2], target[3]}, alpha = 0, trails = {}}
     -- Do not flash an idle dot on first enable when no manual is applied.
     if dir == 0 then state.idle_since = now - 1 end
     self.dot = state
   end
   local px, py = state.x, state.y
   local previous = {state.color[1], state.color[2], state.color[3]}
   state.x = self:_ease(state.x, x, 19.71)
   state.y = self:_ease(state.y, y, 19.71)
   for i = 1, 3 do state.color[i] = self:_ease(state.color[i], target[i], 13.39) end
   if (state.x - px)^2 + (state.y - py)^2 > (scale * 5)^2 then
     state.trails[#state.trails + 1] = {x = px, y = py, color = previous, time = now}
     if #state.trails > 3 then table.remove(state.trails, 1) end
   end
   if dir ~= 0 then state.idle_since = nil
   elseif math.abs(state.x - x) <= scale and math.abs(state.y - y) <= scale then
     state.idle_since = state.idle_since or now
   else state.idle_since = nil end
   local alpha = target[4] or 255
   if state.idle_since and now - state.idle_since > 0.3 then alpha = 0 end
   state.alpha = self:_ease(state.alpha, alpha, 12.64)
   for i = #state.trails, 1, -1 do
     local trail = state.trails[i]
     local fade = 1 - (now - trail.time) / 0.22
     if fade <= 0 then table.remove(state.trails, i)
     elseif state.alpha > 1 then
       self:_glow_dot(trail.x, trail.y, trail.color, state.alpha * fade * 0.25, scale)
     end
   end
   if state.alpha > 1 then self:_glow_dot(state.x, state.y, state.color, state.alpha, scale) end
 end,
 _render_modern = function(self, cx, cy, offset, dir, color, scoped)
   self.pointers = self.pointers or {left = 0, right = 0, forward = 0, scope = 0}
   local state = self.pointers
   state.scope = self:_ease(state.scope, scoped and 1 or 0, 12)
   local y = cy - 19 - state.scope * 20
   local function glyph(x, gy, alpha, text, flags)
     renderer.text(x, gy, color[1], color[2], color[3], math.floor(color[4] * alpha), flags or "a+", 0, text)
   end
   state.left = self:_ease(state.left, dir == 1 and 1 or 0, 6.32)
   state.right = self:_ease(state.right, dir == 2 and 1 or 0, 6.32)
   state.forward = self:_ease(state.forward, dir == 3 and 1 or 0, 6.32)
   if state.right > 0.01 then
     glyph(cx + offset, y, state.right, "∘")
     glyph(cx + offset + 6, y, state.right, "≻")
   end
   if state.left > 0.01 then
     glyph(cx - offset - 10, y, state.left, "∘")
     glyph(cx - offset - 19, y, state.left, "≺")
   end
   -- Pointers originally has left/right only; match its glyph styling for forward.
   if state.forward > 0.01 then
     glyph(cx, cy - offset - 19, state.forward, "⋏", "a+c")
     glyph(cx, cy - offset - 10, state.forward, "∘", "a+c")
   end
 end,

 _font_flags = function(self, name)
   if name == "Pixel" then return "-"
   elseif name == "Bold" then return "b"
   elseif name == "Large" then return "+"
   end
   return ""
 end,
 _clamp = function(_, v, lo, hi)
   if v < lo then return lo end
   if v > hi then return hi end
   return v
 end,
 _read_aa = function(self)
   local body, desync = 0, 0
   pcall(function()
     if antiaim_funcs.get_body_yaw then
       body = tonumber(antiaim_funcs.get_body_yaw()) or 0
     end
   end)
   pcall(function()
     if antiaim_funcs.get_desync then
       desync = tonumber(antiaim_funcs.get_desync()) or 0
     end
   end)
   return body, desync
 end,
 _arrow = function(self, side, cx, cy, size, r, g, b, a)
   size = math.floor(size + 0.5)
   if side < 0 then
     renderer.triangle(
       cx - size, cy,
       cx + size * 0.35, cy - size,
       cx + size * 0.35, cy + size,
       r, g, b, a
     )
   else
     renderer.triangle(
       cx + size, cy,
       cx - size * 0.35, cy - size,
       cx - size * 0.35, cy + size,
       r, g, b, a
     )
   end
 end,
 _bar = function(self, x, y, w, h, frac, r, g, b, a)
   frac = self:_clamp(frac or 0, 0, 1)
   renderer.rectangle(x, y, w, h, 20, 20, 20, math.floor(a * 0.55))
   local fill = math.floor(w * frac + 0.5)
   if fill > 0 then
     renderer.rectangle(x, y, fill, h, r, g, b, a)
   end
 end,
 _render_custom = function(self, menu_item, cx, cy, offset, r, g, b, a)
   local dir = Class.util.antiaim and Class.util.antiaim.manual_direction or 0
   local font = self:_font_flags(menu_item.font and menu_item.font:get() or "Default")
   local left_sym = menu_item.left and menu_item.left:get() or ""
   local right_sym = menu_item.right and menu_item.right:get() or ""
   local fwd_sym = menu_item.forward and menu_item.forward:get() or ""
   local flags = font .. "c"

   -- Draw only the currently applied manual direction; never show an editor preview.
   if left_sym ~= "" and dir == 1 then
     renderer.text(cx - offset, cy, r, g, b, a, flags, 0, left_sym)
   end
   if right_sym ~= "" and dir == 2 then
     renderer.text(cx + offset, cy, r, g, b, a, flags, 0, right_sym)
   end
   if fwd_sym ~= "" and dir == 3 then
     renderer.text(cx, cy - offset, r, g, b, a, flags, 0, fwd_sym)
   end
 end,
 _render_team_skeet = function(self, menu_item, cx, cy, offset, yaw_r, yaw_g, yaw_b, yaw_a)
   -- geometry from aesthetic / G0TH team-skeet: triangles + vertical bars beside them
   local body_r, body_g, body_b, body_a = 56, 158, 252, 255
   pcall(function()
     if menu_item.body_color then
       body_r, body_g, body_b, body_a = menu_item.body_color:get()
     end
   end)

   local off = tonumber(offset) or 42
   if off < 30 then off = 40 end
   local def_r, def_g, def_b, def_a = 35, 35, 35, 150

   local aa_state = Class.util.antiaim
   local dir = 0
   if aa_state and aa_state.manual_applied == true then
     dir = tonumber(aa_state.manual_direction) or 0
   end
   local body_side = 0
   local me = entity.get_local_player()

   -- body side purely from antiaim_funcs (and pose fallback)
   pcall(function()
     local body = tonumber(antiaim_funcs.get_body_yaw()) or 0
     if body < -1 then body_side = -1
     elseif body > 1 then body_side = 1
     end
   end)
   if body_side == 0 and me and entity.is_alive(me) then
     pcall(function()
       local pose = entity.get_prop(me, "m_flPoseParameter", 11)
       if type(pose) == "number" then
         local deg = pose * 120 - 60
         if deg < -2 then body_side = -1
         elseif deg > 2 then body_side = 1
         end
       end
     end)
   end
   -- Desync bars follow the live body-yaw side, independently of Manual yaw.

   -- left triangle
   do
     local r, g, b, a = def_r, def_g, def_b, def_a
     if dir == 1 then r, g, b, a = yaw_r, yaw_g, yaw_b, yaw_a end
     renderer.triangle(
       cx - off - 15, cy + 2,
       cx - off - 2, cy - 7,
       cx - off - 2, cy + 11,
       r, g, b, a
     )
   end
   -- right triangle
   do
     local r, g, b, a = def_r, def_g, def_b, def_a
     if dir == 2 then r, g, b, a = yaw_r, yaw_g, yaw_b, yaw_a end
     renderer.triangle(
       cx + off + 15, cy + 2,
       cx + off + 2, cy - 7,
       cx + off + 2, cy + 11,
       r, g, b, a
     )
   end
   -- vertical desync bars glued to the inner edge of each triangle
   do
     local r, g, b, a = def_r, def_g, def_b, def_a
     if body_side < 0 then r, g, b, a = body_r, body_g, body_b, body_a end
     renderer.rectangle(cx - off, cy - 7, 2, 18, r, g, b, a)
   end
   do
     local r, g, b, a = def_r, def_g, def_b, def_a
     if body_side > 0 then r, g, b, a = body_r, body_g, body_b, body_a end
     renderer.rectangle(cx + off - 2, cy - 7, 2, 18, r, g, b, a)
   end
 end,
 render = function(self)
   local item = Class.ui.menu.visuals_tab.interface.manual_arrows
   if not item or not item.enabled:get() then
     self:_reset_styles()
     self.last_style = nil
     return
   end
   local style = item.style and item.style:get() or "Team Skeet"
   if self.last_style ~= style then self:_reset_styles(); self.last_style = style end
   local player = entity.get_local_player()
   local alive = player and entity.is_alive(player)
   if not alive and (style == "CS2" or style == "Modern" or not ui.is_menu_open()) then
     self:_reset_styles()
     return
   end
   local aa = Class.util.antiaim
   local dir = aa and aa.manual_applied == true and tonumber(aa.manual_direction) or 0
   if dir ~= 1 and dir ~= 2 and dir ~= 3 then dir = 0 end
   if style == "Custom" and dir == 0 then return end
   local width, height = client.screen_size()
   local cx, cy = math.floor(width * 0.5), math.floor(height * 0.5)
   local offset = tonumber(item.offset:get()) or 42
   local color = { (style == "Team Skeet" and item.yaw_color or item.custom_color):get() }
   if style == "Team Skeet" then
     self:_render_team_skeet(item, cx, cy, offset, unpack(color))
   elseif style == "CS2" then
     self:_render_cs2(item, cx, cy, offset, dir, color)
   elseif style == "Modern" then
     local scoped = alive and entity.get_prop(player, "m_bIsScoped")
     self:_render_modern(cx, cy, offset, dir, color, scoped == 1 or scoped == true)
   else
     self:_render_custom(item, cx, cy, offset, unpack(color))
   end
 end,
},
crosshair_indicator = {
 _render_japanese = function(self)
   local player = entity.get_local_player()
   local alive = player and entity.is_alive(player) or false
   local refs = Class.util.reference or {}
   local function active(list)
     if not list or not list[1] then return false end
     local ok, enabled = pcall(ui.get, list[1])
     if not ok or enabled ~= true then return false end
     if list[2] then
       local success, key = pcall(ui.get, list[2])
       return success and key == true
     end
     return true
   end
   local dt = active(refs.rage_double_tap)
   local hs = not dt and active(refs.aa_hideshots)
   local duck = active(refs.rage_fake_duck)
   local damage = Class.visuals.damage_indicator
   local override = damage and damage:_is_override() or false
   local scoped = alive and entity.get_prop(player, "m_bIsScoped")
   local targets = {alive = alive and 1 or 0, scoped = (scoped == 1 or scoped == true) and 1 or 0,
     dt = dt and 1 or 0, hs = hs and 1 or 0, damage = override and 1 or 0}
   self.jp = self.jp or {alive = 0, scoped = 0, dt = 0, hs = 0, damage = 0}
   local state = self.jp
   local frame = math.max(0, math.min(0.1, globals.frametime()))
   for key, target in pairs(targets) do
     local rate = key == "alive" and 14 or 18
     state[key] = state[key] + (target - state[key]) * (1 - math.exp(-rate * frame))
   end
   local alpha = state.alive
   if alpha <= 0.01 then return end
   local width, height = client.screen_size()
   local x, y = width * 0.5 + 24 * state.scoped + 22, height * 0.5 + 42
   local aa = Class.util.antiaim
   local manual = aa and aa.manual_applied == true
   local function line(text, r, g, b, opacity, flags)
     flags = flags or ""
     renderer.text(math.floor(x), math.floor(y), r, g, b, math.floor(opacity * alpha), flags .. "c", 0, text)
     local _, h = renderer.measure_text(flags, text)
     y = y + math.max(h or 8, 8)
   end
   if manual then
     line("リセット YAW", 177, 151, 255, 255)
     line("デフォルト", 255, 0, 0, 255)
   else
     line("てんしのような YAW", 218, 118, 0, 255)
     line("どうてきな", 209, 139, 230, 255)
   end
   if state.dt > 0.02 then
     local charged = false
     if antiaim_funcs and antiaim_funcs.get_double_tap then
       local ok, value = pcall(antiaim_funcs.get_double_tap)
       charged = ok and value == true
     end
     line(duck and "倍の (フェイクダック)" or "倍の", charged and 0 or 255, charged and 255 or 0, 0, 255 * state.dt)
   elseif state.hs > 0.02 then
     line(duck and "アンチエイム (フェイクダック)" or "アンチエイム", duck and 255 or 209,
       duck and 0 or 139, duck and 0 or 230, 255 * state.hs)
   end
   if state.damage > 0.02 and damage then
     line("ダメージ " .. tostring(damage:_get_damage(override)), 255, 255, 255, 225 * state.damage, "-")
   end
 end,

 render = function(self)
   local item = Class.ui.menu.visuals_tab.interface.crosshair_indicator
   if not item or not item.enabled:get() then
     self.scope_progress = 0
     self.jp = nil
     return
   end
   if item.mode and item.mode:get() == "Japanese" then
     self:_render_japanese()
     return
   end
   self.jp = nil

   local local_player = entity.get_local_player()
   local menu_open = ui.is_menu_open()
   if (not local_player or not entity.is_alive(local_player)) and not menu_open then return end

   local screen_w, screen_h = client.screen_size()
   local cx, cy = math.floor(screen_w * 0.5), math.floor(screen_h * 0.5)
   local r, g, b, a = item.color:get()
   a = math.max(0, math.min(255, tonumber(a) or 255))
   if a < 1 then return end

   local mode = item.mode and item.mode:get() or "Default"
   local japanese = mode == "Japanese"
   local ideal_yaw = false
   local runes = false
   local selected_options = {}
   pcall(function() selected_options = item.options:get() or {} end)
   local function option_on(name)
     if type(selected_options) ~= "table" then return false end
     if selected_options[name] == true then return true end
     for i = 1, #selected_options do
       if selected_options[i] == name then return true end
     end
     return false
   end
   local fade_on_scope = option_on("Fade on Scope")
   local slide_on_scope = option_on("Slide on Scope")

   local scoped = false
   if local_player and entity.is_alive(local_player) then
     local ok_scope, is_scoped = pcall(entity.get_prop, local_player, "m_bIsScoped")
     if ok_scope and (is_scoped == true or is_scoped == 1) then
       scoped = true
     end
   end
   if menu_open and not scoped then
     -- preview slide in menu when options enabled so it is obvious
   end

   -- Smooth a single scope progress value so fade and slide stay synchronized.
   local target_progress = (scoped and (fade_on_scope or slide_on_scope)) and 1 or 0
   local frame_time = 1 / 60
   pcall(function() frame_time = math.max(0, math.min(0.05, globals.frametime())) end)
   self.scope_progress = self.scope_progress or 0
   local blend = math.min(1, frame_time * 12)
   self.scope_progress = self.scope_progress + (target_progress - self.scope_progress) * blend
   if math.abs(target_progress - self.scope_progress) < 0.002 then
     self.scope_progress = target_progress
   end
   local scope_progress = math.max(0, math.min(1, self.scope_progress))

   local effective_alpha = a
   if fade_on_scope then
     effective_alpha = math.floor(a * (1 - scope_progress * 0.72) + 0.5)
   end

   local offset_x, offset_y = 0, 0
   local direction = item.direction and item.direction:get() or "Right"
   local gap = 17
   pcall(function() gap = tonumber(item.gap_y:get()) or 17 end)

   -- One Distance slider: Default = Y only; Japanese = shared X + Y.
   local align_title, align_line = "bc", "-c"
   local jp_align_title, jp_align_line = "bc", "-c"
   local side_mode = false
   if not japanese then
     offset_x = 0
     offset_y = gap
     if slide_on_scope and scope_progress > 0 then
       local distance = 52 * scope_progress
       side_mode = scope_progress > 0.02
       if direction == "Left" then
         offset_x = -distance
         if side_mode then
           align_title, align_line = "b", "-"
         end
       else
         offset_x = distance
         if side_mode then
           align_title, align_line = "b", "-"
         end
       end
       if side_mode and direction == "Left" then
         align_title, align_line = "br", "-r"
       end
     end
   else
     offset_y = gap
     if direction == "Left" then
       offset_x = -gap
       jp_align_title, jp_align_line = "br", "-r"
     else
       offset_x = gap
       jp_align_title, jp_align_line = "b", "-"
     end
   end

   local reference = Class.util.reference or {}
   local binds = {}
   local bind_labels = japanese and {
     DT = "二連打",
     HS = "隠し撃ち",
     FD = "偽しゃがみ",
     QP = "クイックピーク",
     SW = "低速歩行",
     FS = "自由旋回",
   } or {}
   local function active(refs, bind_mode)
     if not refs or not refs[1] then return false end
     local ok, enabled = pcall(ui.get, refs[1])
     if not ok or not enabled then return false end
     if refs[2] then
       local hotkey_ok, hotkey = pcall(ui.get, refs[2])
       if hotkey_ok and type(hotkey) == "boolean" then
         if bind_mode == "checkbox" then return enabled end
         return hotkey
       end
     end
     return enabled and true or false
   end
   local function add_bind(label, refs, bind_mode)
     if active(refs, bind_mode) then
       binds[#binds + 1] = bind_labels[label] or label
     end
   end
   add_bind("DT", reference.rage_double_tap)
   add_bind("HS", reference.aa_hideshots)
   if not japanese and not ideal_yaw then
     add_bind("FD", reference.rage_fake_duck, "checkbox")
     add_bind("QP", reference.rage_peek_assist)
     add_bind("SW", reference.aa_slow_walk)
     add_bind("FS", reference.aa_freestanding)
   end
   -- Force Shot appears in the same future/crosshair indicator stack as DT/HS.
   do
     local force = Class.gamesense and Class.gamesense.force_shot
     local menu = force and force._menu and force:_menu()
     local show = false
     if menu and menu.enabled and menu.enabled:get() then
       local indicator_on = true
       pcall(function() indicator_on = menu.indicator:get() and true or false end)
       if indicator_on and force:_hotkey_active(menu) then
         show = true
       end
     end
     if show then
       local label = japanese and "FORCE" or "FORCE"
       binds[#binds + 1] = label
     end
   end

   local condition = "STANDING"
   pcall(function()
     local current = Class.util.antiaim and Class.util.antiaim.current_condition
     if type(current) == "string" and current ~= "" then condition = current:upper() end
   end)
   if japanese then
     local condition_labels = {
       SHARED = "共通",
       STANDING = "通常",
       RUNNING = "走行中",
       SLOWING = "低速移動",
       AIR = "空中",
       ["AIR CROUCH"] = "空中しゃがみ",
       CROUCH = "しゃがみ中",
       SNEAKING = "忍び歩き",
       FREESTANDING = "自由旋回",
       ["LEGIT AA"] = "正規アンチエイム",
     }
     condition = condition_labels[condition] or condition
   end

   local title = japanese and "アフタゲロウ" or "afterglow.yaw"
   local _, title_h = renderer.measure_text("b", title)
   if runes then title_h = 9 end

   local title_gradient
   -- Accent follows real yaw side (not body/desync): left <-> right, tick-smoothed.
   local yaw_value = 0
   do
     local value = nil
     pcall(function()
       local aa = require("gamesense/antiaim_funcs")
       local abs_yaw = nil
       if aa and aa.get_abs_yaw then
         abs_yaw = aa.get_abs_yaw()
       end
       local cam_p, cam_y = client.camera_angles()
       if type(abs_yaw) == "number" and type(cam_y) == "number" then
         local d = (abs_yaw - cam_y + 180) % 360 - 180
         value = d
       end
     end)
     if value == nil then
       local lp = entity.get_local_player()
       if lp and entity.is_alive(lp) then
         local ok_y, eye_y = pcall(entity.get_prop, lp, "m_angEyeAngles[1]")
         local cam_p, cam_y = client.camera_angles()
         if ok_y and type(eye_y) == "number" and type(cam_y) == "number" then
           value = (eye_y - cam_y + 180) % 360 - 180
         end
       end
     end
     if type(value) == "number" then
       yaw_value = value
     end
     local dir = Class.util.antiaim and Class.util.antiaim.manual_direction or 0
     if dir == 1 then
       yaw_value = -60
     elseif dir == 2 then
       yaw_value = 60
     end
   end
   -- 0 = left accent, 1 = right accent
   local target_travel = yaw_value >= 0 and 1 or 0
   if yaw_value > -8 and yaw_value < 8 then
     target_travel = (self.title_travel or 0) >= 0.5 and 1 or 0
   end
   self.title_travel = self.title_travel or target_travel
   local ft = 0.015
   pcall(function()
     ft = math.max(0.0, math.min(0.05, globals.frametime()))
   end)
   -- ~8–10 ticks to cross: sharp but smooth
   local blend = math.min(1, ft * 14)
   self.title_travel = self.title_travel + (target_travel - self.title_travel) * blend
   if math.abs(target_travel - self.title_travel) < 0.002 then
     self.title_travel = target_travel
   end
   local travel = self.title_travel
   title_gradient = title

   local text_x = cx + offset_x
   local text_y = cy + offset_y

   -- Draw runes from line segments rather than text glyphs. This keeps the
   -- Runes style visible even when the selected in-game font has no Unicode.
   local rune_glyphs = {
     a = {{1,0,1,10},{1,2,7,0},{1,5,7,3}},
     b = {{1,0,1,10},{1,2,7,4},{7,4,1,7},{1,7,7,9}},
     c = {{1,0,1,10},{1,2,7,5},{1,7,7,10}},
     d = {{1,0,7,5},{7,5,1,10},{1,10,7,5},{7,5,1,0}},
     e = {{1,0,1,10},{7,0,7,10},{1,4,7,8}},
     f = {{1,0,1,10},{1,2,7,0},{1,6,7,4}},
     g = {{1,0,7,10},{7,0,1,10}},
     h = {{1,0,1,10},{7,0,7,10},{1,3,7,7}},
     i = {{4,0,4,10}},
     j = {{1,0,1,10},{1,3,7,0},{1,7,7,10}},
     k = {{1,0,1,10},{1,2,7,5},{7,5,1,8}},
     l = {{1,0,1,10},{1,7,7,2}},
     m = {{1,0,1,10},{7,0,7,10},{1,3,7,7}},
     n = {{1,0,1,10},{1,6,7,2}},
     o = {{1,0,1,10},{1,2,7,0},{1,10,7,5},{7,0,7,5}},
     p = {{1,0,1,10},{1,2,7,2},{7,2,7,6},{7,6,1,6}},
     q = {{1,0,7,5},{7,5,1,10},{1,10,7,5}},
     r = {{1,0,1,10},{1,2,7,2},{7,2,7,5},{7,5,1,5}},
     s = {{7,0,1,3},{1,3,7,6},{7,6,1,10}},
     t = {{1,0,1,10},{1,2,7,2},{1,0,7,0}},
     u = {{1,0,1,10},{1,2,7,0},{7,0,7,10}},
     v = {{1,0,4,10},{4,10,7,0}},
     w = {{1,0,2,10},{2,10,5,3},{5,3,7,10},{7,10,8,0}},
     x = {{1,0,1,10},{1,3,7,0},{1,3,7,6}},
     y = {{1,0,7,0},{7,0,4,5},{4,5,4,10}},
     z = {{1,0,1,10},{7,0,7,10},{1,3,7,7}},
     ["/"] = {{2,10,7,0}},
   }
   local function draw_rune_text(value, center_x, baseline_y, color_for_char)
     value = tostring(value or ""):lower()
     local glyph_scale = 0.75
     local glyph_advance, space_advance = 7.5, 3.75
     local width = 0
     for index = 1, #value do
       local char = value:sub(index, index)
       width = width + (char == " " and space_advance or (char == "." and 5 or glyph_advance))
     end
     local cursor_x = center_x - width * 0.5
     local top_y = baseline_y - 7.5
     local total = math.max(#value, 1)
     for index = 1, #value do
       local char = value:sub(index, index)
       local cr, cg, cb, ca = color_for_char(index, total)
       if char == " " then
         cursor_x = cursor_x + space_advance
       elseif char == "." then
         -- A small diamond divider, also drawn from supported line primitives.
         local mx, my = cursor_x + 1.5, top_y + 5.25
         renderer.line(mx, my - 1.5, mx + 1.5, my, cr, cg, cb, ca)
         renderer.line(mx + 1.5, my, mx, my + 1.5, cr, cg, cb, ca)
         renderer.line(mx, my + 1.5, mx - 1.5, my, cr, cg, cb, ca)
         renderer.line(mx - 1.5, my, mx, my - 1.5, cr, cg, cb, ca)
         cursor_x = cursor_x + 5
       else
         local segments = rune_glyphs[char] or rune_glyphs.i
         for segment_index = 1, #segments do
           local segment = segments[segment_index]
           local x1, y1 = cursor_x + segment[1] * glyph_scale, top_y + segment[2] * glyph_scale
           local x2, y2 = cursor_x + segment[3] * glyph_scale, top_y + segment[4] * glyph_scale
           renderer.line(x1, y1, x2, y2, cr, cg, cb, ca)
           renderer.line(x1 + 0.45, y1, x2 + 0.45, y2, cr, cg, cb, ca)
         end
         cursor_x = cursor_x + glyph_advance
       end
     end
   end

   local function draw_glow_text(x, y, tr, tg, tb, ta, flags, value)
     local glow_a = math.floor(ta * 0.28)
     if glow_a > 0 then
       for dx = -1, 1 do
         for dy = -1, 1 do
           if dx ~= 0 or dy ~= 0 then
             renderer.text(x + dx, y + dy, tr, tg, tb, glow_a, flags, 0, value)
           end
         end
       end
       renderer.text(x, y - 1, tr, tg, tb, math.floor(ta * 0.18), flags, 0, value)
     end
     renderer.text(x, y, tr, tg, tb, ta, flags, 0, value)
   end

   if runes then
     local start_color = self.rune_title_start or {82, 160, 190}
     local end_color = self.rune_title_end or {190, 230, 242}
     draw_rune_text(title, text_x, text_y, function(index, total)
       if not self.rune_gradient then
         return start_color[1], start_color[2], start_color[3], effective_alpha
       end
       local phase = (index - 1) / math.max(total - 1, 1)
       return
         start_color[1] + (end_color[1] - start_color[1]) * phase,
         start_color[2] + (end_color[2] - start_color[2]) * phase,
         start_color[3] + (end_color[3] - start_color[3]) * phase,
         effective_alpha
     end)
   elseif japanese then
     -- Soft gold title glow + edge alignment
     local tr = math.max(0, math.min(255, 235 + math.floor((r - 140) * 0.25)))
     local tg = math.max(0, math.min(255, 185 + math.floor((g - 110) * 0.20)))
     local tb = math.max(0, math.min(255, 95 + math.floor((b - 115) * 0.15)))
     draw_glow_text(text_x, text_y, tr, tg, tb, effective_alpha, jp_align_title, title)
   else
     local title_w = select(1, renderer.measure_text("b", title)) or 0
     local draw_x = text_x
     if align_title:find("c", 1, true) then
       draw_x = math.floor(text_x - title_w * 0.5 + 0.5)
     elseif align_title:find("r", 1, true) then
       draw_x = math.floor(text_x - title_w + 0.5)
     end
     local cursor = draw_x
     local len = #title
     if len < 1 then len = 1 end
     -- Soft band around travel so color bleeds across letters while moving side to side.
     local band = 0.42
     for i = 1, #title do
       local ch = title:sub(i, i)
       local unit = (i - 1) / math.max(len - 1, 1)
       -- Left letters hot when travel~0, right letters hot when travel~1.
       local mix = 1 - math.abs(unit - travel) / band
       if mix < 0 then mix = 0 end
       if mix > 1 then mix = 1 end
       mix = mix * mix * (3 - 2 * mix)
       local cr = math.floor(255 + (r - 255) * mix + 0.5)
       local cg = math.floor(255 + (g - 255) * mix + 0.5)
       local cb = math.floor(255 + (b - 255) * mix + 0.5)
       renderer.text(cursor, text_y, cr, cg, cb, effective_alpha, "b", 0, ch)
       local cw = select(1, renderer.measure_text("b", ch)) or 0
       cursor = cursor + cw
     end
   end

   local binds_text = #binds > 0 and table.concat(binds, "   ") or nil
   -- Conditions and hotkeys stay white in every visual mode; only the title is tinted.
   local line_r, line_g, line_b = 255, 255, 255
   local function draw_pixel_line(line)
     if not line or line == "" then return end
     if runes then
       draw_rune_text(line, text_x, text_y, function()
         return line_r, line_g, line_b, effective_alpha
       end)
       text_y = text_y + 9
       return
     end
     local line_w, line_h = renderer.measure_text("-", line)
     line_w = line_w or 0
     line_h = line_h or 10
     local draw_x = text_x
     if align_line:find("c", 1, true) then
       draw_x = math.floor(text_x - line_w * 0.5 + 0.5)
     elseif align_line:find("r", 1, true) then
       draw_x = math.floor(text_x - line_w + 0.5)
     end
     renderer.text(draw_x, text_y, line_r, line_g, line_b, effective_alpha, "-", 0, line)
     text_y = text_y + line_h + 2
   end

   if japanese then
     -- Equal step + soft glow; bottom line only DT / HS
     local jp_step = 12
     text_y = text_y + jp_step
     local function draw_jp_line(line, tr, tg, tb)
       if not line or line == "" then return end
       draw_glow_text(text_x, text_y, tr, tg, tb, effective_alpha, jp_align_line, line)
       text_y = text_y + jp_step
     end
     draw_jp_line("【" .. condition .. "】", 195, 150, 235)
     if #binds > 0 then
       local framed_binds = {}
       for index = 1, #binds do
         framed_binds[index] = "「" .. binds[index] .. "」"
       end
       draw_jp_line(table.concat(framed_binds, " ・ "), 120, 220, 130)
     end
   else
     text_y = text_y + title_h + 2
     draw_pixel_line(condition)
     if binds_text then draw_pixel_line(binds_text) end
   end
 end,
},

zoom_animation = {
 _callback = nil,
 _smooth_fov = nil,
 _scope_active = false,
 _on_override_view = function(self, e)
   local menu_item = Class.ui.menu.visuals_tab.other.zoom_animation
   if not menu_item or not e or type(e.fov) ~= "number" then return end

   local enabled, speed = false, 60
   pcall(function()
     enabled = menu_item.enabled:get() and true or false
     speed = tonumber(menu_item.speed:get()) or 60
   end)

   local me = entity.get_local_player()
   local weapon = me and entity.get_player_weapon(me)
   local zoom_level = weapon and entity.get_prop(weapon, "m_zoomLevel") or 0
   local scoped = me and entity.is_alive(me) and entity.get_prop(me, "m_bIsScoped") == 1
   local factor = math.max(0.05, math.min(1, speed / 100))
   local target_fov = e.fov

   if not enabled then
     self._smooth_fov = nil
     self._scope_active = false
     return
   end

   if self._smooth_fov == nil then
     self._smooth_fov = e.fov
   end
   self._smooth_fov = Class.motion.window(self._smooth_fov, target_fov, factor)
   e.fov = math.max(1, self._smooth_fov)
 end,
 setup = function(self)
   if self._callback then return end
   self._callback = function(e) self:_on_override_view(e) end
   client.set_event_callback("override_view", self._callback)
 end,
 shutdown = function(self)
   if self._callback then
     pcall(client.unset_event_callback, "override_view", self._callback)
     self._callback = nil
   end
   self._smooth_fov = nil
   self._scope_active = false
 end,
},
aspect_ratio = {
 _last = 0,
 _smooth = 0,
 update = function(self)
   local menu_item = Class.ui.menu.visuals_tab.other.aspect_ratio
   if not menu_item or not menu_item.enabled:get() then
     if self._last ~= 0 or self._smooth ~= 0 then
       pcall(function() cvar.r_aspectratio:set_float(0) end)
       self._last = 0
       self._smooth = 0
     end
     return
   end

   local preset = menu_item.preset:get()
   local value
   if preset == "5:4" then value = 1.25
   elseif preset == "4:3" then value = 1.33
   elseif preset == "16:10" then value = 1.6
   elseif preset == "16:9" then value = 16 / 9
   else value = menu_item.amount:get() / 100 end

   self._smooth = Class.motion.window(self._smooth, value, 0.24)
   if math.abs(self._last - self._smooth) > 0.0001 then
     pcall(function() cvar.r_aspectratio:set_float(self._smooth) end)
     self._last = self._smooth
   end
 end,
 reset = function(self)
   pcall(function() cvar.r_aspectratio:set_float(0) end)
   self._last = 0
   self._smooth = 0
 end
},
viewmodel_changer = {
 _was_enabled = false,
 _last_written = { x = nil, y = nil, z = nil, viewmodel_fov = nil },
 _smooth = { x = nil, y = nil, z = nil, fov = nil },
 update = function(self)
   local menu = Class.ui and Class.ui.menu
   local viewmodel_ui = menu and menu.visuals_tab and menu.visuals_tab.other and menu.visuals_tab.other.viewmodel_changer
   if not viewmodel_ui or not viewmodel_ui.enabled then return end
   local enabled = false
   pcall(function() enabled = viewmodel_ui.enabled:get() and true or false end)
   if not enabled then
     if self._was_enabled then
       Class.util:restore_viewmodel()
       self._last_written = { x = nil, y = nil, z = nil, viewmodel_fov = nil }
       self._smooth = { x = nil, y = nil, z = nil, fov = nil }
       self._was_enabled = false
     end
     return
   end
   if not self._was_enabled then
     Class.util:save_viewmodel_state()
     local sx, sy, sz, sf = 0, 0, 0, 68
     pcall(function() sx = cvar.viewmodel_offset_x:get_float() or 0 end)
     pcall(function() sy = cvar.viewmodel_offset_y:get_float() or 0 end)
     pcall(function() sz = cvar.viewmodel_offset_z:get_float() or 0 end)
     pcall(function() sf = cvar.viewmodel_fov:get_float() or 68 end)
     self._smooth = { x = sx, y = sy, z = sz, fov = sf }
   end
   self._was_enabled = true
   local target_x = viewmodel_ui.position.x:get() / 10
   local target_y = viewmodel_ui.position.y:get() / 10
   local target_z = viewmodel_ui.position.z:get() / 10
   local target_fov = (tonumber(viewmodel_ui.fov:get()) or 680) * 0.1
   self._smooth.x = Class.motion.window(self._smooth.x, target_x, 0.30)
   self._smooth.y = Class.motion.window(self._smooth.y, target_y, 0.30)
   self._smooth.z = Class.motion.window(self._smooth.z, target_z, 0.30)
   self._smooth.fov = Class.motion.window(self._smooth.fov, target_fov, 0.30)
   local x, y, z, fov = self._smooth.x, self._smooth.y, self._smooth.z, self._smooth.fov
   local lx, ly, lz = self._last_written.x, self._last_written.y, self._last_written.z
   if not lx or math.abs(x - lx) > 0.001 or math.abs(y - ly) > 0.001 or math.abs(z - lz) > 0.001 then
     pcall(function()
       cvar.viewmodel_offset_x:set_raw_float(x)
       cvar.viewmodel_offset_y:set_raw_float(y)
       cvar.viewmodel_offset_z:set_raw_float(z)
     end)
     self._last_written.x, self._last_written.y, self._last_written.z = x, y, z
   end
   if self._last_written.viewmodel_fov == nil or math.abs(self._last_written.viewmodel_fov - fov) > 0.001 then
     pcall(function() cvar.viewmodel_fov:set_raw_float(fov) end)
     self._last_written.viewmodel_fov = fov
   end
 end,
},
opposite_knife_hand = {
 baseline = nil,
 was_knife = false,
 _was_enabled = false,
 update = function(self)
   local viewmodel_ui = Class.ui.menu.visuals_tab.other.viewmodel_changer
   local is_enabled = viewmodel_ui and viewmodel_ui.enabled and viewmodel_ui.enabled:get() and viewmodel_feature_enabled("Opposite Knife Hand")
   if not is_enabled then
     if self._was_enabled and self.baseline ~= nil then
       pcall(function() cvar.cl_righthand:set_int(self.baseline) end)
     end
     self.baseline = nil
     self.was_knife = false
     self._was_enabled = false
     return
   end
   self._was_enabled = true
   local local_player = entity.get_local_player()
   if not local_player or not entity.is_alive(local_player) then return end
   local is_knife = false
   local wpn = entity.get_player_weapon(local_player)
   if wpn then
     local cls = entity.get_classname(wpn) or ""
     if cls == "CKnife" or cls:lower():find("knife", 1, true) then
       is_knife = true
     end
   end
   local current = 1
   pcall(function() current = cvar.cl_righthand:get_int() or 1 end)
   if current ~= 0 and current ~= 1 then current = 1 end
   if not is_knife then
     if self.was_knife and self.baseline ~= nil then
       pcall(function() cvar.cl_righthand:set_int(self.baseline) end)
       pcall(function() current = cvar.cl_righthand:get_int() or self.baseline end)
     end
     self.baseline = current
     self.was_knife = false
     return
   end
   if self.baseline == nil then
     self.baseline = current
   end
   local target = (self.baseline == 1) and 0 or 1
   if current ~= target then
     pcall(function() cvar.cl_righthand:set_int(target) end)
   end
   self.was_knife = true
 end,
 shutdown = function(self)
   if self.baseline ~= nil then
     pcall(function() cvar.cl_righthand:set_int(self.baseline) end)
   end
   self.baseline = nil
   self.was_knife = false
   self._was_enabled = false
 end,
},
lock_bob = {
 _active = false,
 _saved = nil,
 _cvars = {
  {name = "cl_bob_lower_amt", value = 0},
  {name = "cl_bobamt_lat", value = 0},
  {name = "cl_bobamt_vert", value = 0},
 },
 _save = function(self)
  if self._saved then return end
  self._saved = {}
  for i = 1, #self._cvars do
    local item = self._cvars[i]
    local c = cvar[item.name]
    local value
    if c then pcall(function() value = c:get_float() end) end
    self._saved[item.name] = value
  end
 end,
 _apply = function(self)
  self:_save()
  for i = 1, #self._cvars do
    local item = self._cvars[i]
    local c = cvar[item.name]
    if c then pcall(function() c:set_float(item.value) end) end
  end
 end,
 restore = function(self)
  if not self._saved then
    self._active = false
    return
  end
  for i = 1, #self._cvars do
    local item = self._cvars[i]
    local c = cvar[item.name]
    local value = self._saved[item.name]
    if c and value ~= nil then pcall(function() c:set_float(value) end) end
  end
  self._saved = nil
  self._active = false
 end,
 update = function(self)
  local viewmodel_ui = Class.ui.menu.visuals_tab.other.viewmodel_changer
  local enabled = false
  pcall(function()
    enabled = viewmodel_ui and viewmodel_ui.enabled:get() and viewmodel_feature_enabled("Lock Bob")
  end)
  if not enabled then
    if self._active then self:restore() end
    return
  end
  self._active = true
  self:_apply()
 end,
 shutdown = function(self)
  self:restore()
 end,
},
damage_indicator = {
 _dmg_ref = nil,
 _ovr_enabled = nil,
 _ovr_hotkey = nil,
 _ovr_value = nil,
 pos = { x = nil, y = nil },
 target_pos = { x = nil, y = nil },
 dragging = false,
 drag_offset = { x = 0, y = 0 },
 setup = function(self)
   pcall(function()
     self._dmg_ref = ui.reference("RAGE", "Aimbot", "Minimum damage")
   end)
   pcall(function()
     local a, b, c = ui.reference("RAGE", "Aimbot", "Minimum damage override")
     self._ovr_enabled = a
     self._ovr_hotkey = b
     self._ovr_value = c
   end)
   local screen_width, screen_height = client.screen_size()
   local def_x = math.floor(screen_width * 0.5 + 20)
   local def_y = math.floor(screen_height * 0.5 - 30)
   local x, y = Class.util.window_pos:get("dmg_x", "dmg_y", def_x, def_y)
   self.pos.x, self.pos.y = x, y
   self.target_pos.x, self.target_pos.y = x, y
 end,
 save_pos = function(self)
   Class.util.window_pos:set("dmg_x", "dmg_y", self.target_pos.x, self.target_pos.y)
 end,
 handle_drag = function(self, bx, by, bw, bh)
   if not ui.is_menu_open() then
     if self.dragging then
       self.dragging = false
       self:save_pos()
     end
     return
   end
   local mouse_x, mouse_y = ui.mouse_position()
   local down = client.key_state(0x01)
   local pad = 8
   local hovered = mouse_x >= bx - pad and mouse_x <= bx + bw + pad and mouse_y >= by - pad and mouse_y <= by + bh + pad
   if down and not self.dragging and hovered then
     self.dragging = true
     self.drag_offset.x = mouse_x - self.target_pos.x
     self.drag_offset.y = mouse_y - self.target_pos.y
   end
   if self.dragging then
     if down then
       local screen_width, screen_height = client.screen_size()
       self.target_pos.x = Class.util.clamp(mouse_x - self.drag_offset.x, 0, screen_width - math.max(bw, 8))
       self.target_pos.y = Class.util.clamp(mouse_y - self.drag_offset.y, 0, screen_height - math.max(bh, 8))
     else
     self.dragging = false
     self:save_pos()
   end
 end
 end,
 _is_override = function(self)
   if not self._ovr_enabled or not self._ovr_hotkey then return false end
   local a, b = false, false
   pcall(function()
     a = ui.get(self._ovr_enabled)
     b = ui.get(self._ovr_hotkey)
   end)
   return a and b
 end,
 _get_damage = function(self, override)
   if override and self._ovr_value then
     local v = 0
     pcall(function() v = ui.get(self._ovr_value) end)
     return v
   end
   if self._dmg_ref then
     local v = 0
     pcall(function() v = ui.get(self._dmg_ref) end)
     return v
   end
   return 0
 end,
 _text = function(self, override)
   local damage = self:_get_damage(override)
   if damage == 0 then return "AUTO" end
   if damage > 100 then return string.format("+%d", damage - 100) end
   return tostring(damage)
 end,
 render = function(self)
   local element = Class.ui.menu.visuals_tab.interface.damage_indicator
   if not element or not element.enabled:get() then return end
   local local_player = entity.get_local_player()
   local menu_open = ui.is_menu_open()
   if (not local_player or not entity.is_alive(local_player)) and not menu_open then return end
   local is_override = self:_is_override()
   if element.only_if_active:get() and not is_override and not menu_open then return end
   local font_map = { Default = "", Small = "-", Bold = "b" }
   local flags = font_map[element.font:get()] or ""
   local r, g, b, a
   if is_override then
     r, g, b, a = element.active_color:get()
   else
   r, g, b, a = element.inactive_color:get()
 end
 a = a or 255
 local text = self:_text(is_override)
 local text_width, text_height = renderer.measure_text(flags, text)
 text_width, text_height = text_width or 24, text_height or 12
 if not self.pos.x then
   local screen_width, screen_height = client.screen_size()
   self.pos.x = math.floor(screen_width * 0.5 + 20)
   self.pos.y = math.floor(screen_height * 0.5 - 30)
   self.target_pos.x, self.target_pos.y = self.pos.x, self.pos.y
 end
 self.pos.x = self.target_pos.x
 self.pos.y = self.target_pos.y
 local x, y = self.pos.x, self.pos.y
 if menu_open then
   self:handle_drag(x, y, text_width, text_height)
 end
 renderer.text(math.floor(x), math.floor(y), r, g, b, a, flags, nil, text)
 end,
},

animation_breaker = {
 _ffi_helper = function(self, cmd_number)
   if not cmd_number or cmd_number == 0 then return nil end
   local success, result = pcall(function()
     if not pcall(ffi.typeof, "bt_cusercmd_t") then
       ffi.cdef[[
       typedef struct {
        struct bt_cusercmd_t (*cusercmd)();
        int     command_number;
        int     tick_count;
        float   view[3];
        float   aim[3];
        float   move[3];
        int     buttons;
       } bt_cusercmd_t;
      ]]
    end
    if not pcall(ffi.typeof, "bt_get_usercmd") then
      ffi.cdef[[
      typedef bt_cusercmd_t*(__thiscall* bt_get_usercmd)(void* input, int, int command_number);
      ]]
    end
    local sig = client.find_signature("client.dll", "\xB9\xCC\xCC\xCC\xCC\x8B\x40\x38\xFF\xD0\x84\xC0\x0F\x85")
    if not sig then return nil end
    local vtbl = ffi.cast("void***", ffi.cast("void**", ffi.cast("uintptr_t", sig) + 1)[0])
    local location = ffi.cast("bt_get_usercmd", vtbl[0][8])
    return location(vtbl, 0, cmd_number)
  end)
  if success then return result end
  return nil
end,
_get_airwalk_animstate = function(self, local_player)
  if not local_player then return nil end
  local ok, result = pcall(function()
    if not pcall(ffi.typeof, "afterglow_airwalk_animstate_t") then
      ffi.cdef[[
        typedef struct {
          char pad[0x124];
          float flAffectedFraction;
        } afterglow_airwalk_animstate_t;
      ]]
    end

    if not self._airwalk_entity_list or not self._airwalk_get_client_entity then
      local interface = client.create_interface("client.dll", "VClientEntityList003")
      if interface == nil or tonumber(ffi.cast("uintptr_t", interface)) == 0 then
        return nil
      end
      local entity_list = ffi.cast("void***", interface)
      if entity_list == nil or tonumber(ffi.cast("uintptr_t", entity_list)) == 0 then
        return nil
      end
      local get_client_entity = entity_list[0][3]
      if get_client_entity == nil then return nil end
      self._airwalk_entity_list = entity_list
      self._airwalk_get_client_entity = ffi.cast(
        "void*(__thiscall*)(void*, int)", get_client_entity
      )
    end

    local entity_pointer = self._airwalk_get_client_entity(self._airwalk_entity_list, local_player)
    if entity_pointer == nil or tonumber(ffi.cast("uintptr_t", entity_pointer)) == 0 then
      return nil
    end

    local entity_address = tonumber(ffi.cast("uintptr_t", entity_pointer))
    local animstate = ffi.cast(
      "afterglow_airwalk_animstate_t**", entity_address + 0x9960
    )[0]
    if animstate == nil or tonumber(ffi.cast("uintptr_t", animstate)) == 0 then
      return nil
    end
    return animstate
  end)
  if ok then return result end
  return nil
end,
_set_air_walking = function(self, local_player, active)
  if not local_player then return false end
  if active then
    local animstate = self:_get_airwalk_animstate(local_player)
    if not animstate then return false end

    if self._airwalk_player ~= local_player then
      self._airwalk_player = local_player
      self._saved_airwalk_fraction = nil
    end
    if self._saved_airwalk_fraction == nil then
      local saved = tonumber(animstate.flAffectedFraction)
      if saved == nil then return false end
      self._saved_airwalk_fraction = saved
    end

    self:_set_pose_parameter(local_player, 0, 7)
    animstate.flAffectedFraction = 1
    return true
  end

  local target = local_player or self._airwalk_player
  if self._airwalk_player ~= nil and (target == nil or target == self._airwalk_player) then
    local animstate = self:_get_airwalk_animstate(self._airwalk_player)
    if animstate and self._saved_airwalk_fraction ~= nil then
      animstate.flAffectedFraction = self._saved_airwalk_fraction
    end
    self._airwalk_player = nil
    self._saved_airwalk_fraction = nil
  end
  if target then self:_restore_pose_parameter(target, 7) end
  return true
end,
_prepare_anim_player = function(self, local_player)
  if not local_player then return end
  if self._anim_player ~= local_player then
    if self._anim_player then
      self:_restore_pose_parameter(self._anim_player, 0)
      self:_restore_pose_parameter(self._anim_player, 1)
      self:_restore_pose_parameter(self._anim_player, 6)
      self:_set_air_walking(self._anim_player, false)
      self:_restore_anim_overlay(self._anim_player)
    end
    self._anim_player = local_player
    self._saved_pose_parameters = {}
    self._saved_overlay_weight = nil
    self._overlay_player = nil
    self._ground_jitter_phase = nil
    self._ground_jitter_delay = nil
    self._ground_jitter_value = nil
    self._ground_moonwalk_active = false
    self._air_pose_target = nil
    self._airwalk_player = nil
    self._saved_airwalk_fraction = nil
    self._earthshake_tick = nil
    self._earthshake_weight = nil
  end
end,
_save_pose_parameter = function(self, local_player, index)
  self:_prepare_anim_player(local_player)
  self._saved_pose_parameters = self._saved_pose_parameters or {}
  if self._saved_pose_parameters[index] ~= nil then return end
  local ok, value = pcall(entity.get_prop, local_player, "m_flPoseParameter", index)
  if ok and type(value) == "number" then
    self._saved_pose_parameters[index] = value
  end
end,
_set_pose_parameter = function(self, local_player, value, index)
  if not local_player then return end
  self:_save_pose_parameter(local_player, index)
  value = math.max(0, math.min(1, tonumber(value) or 0))
  pcall(entity.set_prop, local_player, "m_flPoseParameter", value, index)
end,
_restore_pose_parameter = function(self, local_player, index)
  local saved = self._saved_pose_parameters and self._saved_pose_parameters[index]
  if local_player and saved ~= nil then
    pcall(entity.set_prop, local_player, "m_flPoseParameter", saved, index)
    self._saved_pose_parameters[index] = nil
  end
end,
_update_anim_overlay = function(self, overlay_index, weight)
  local local_player = entity.get_local_player()
  if not local_player then return false end
  self:_prepare_anim_player(local_player)
  local success, self_index = pcall(c_entity.new, local_player)
  if not success or not self_index then return false end
  local overlay = self_index:get_anim_overlay(overlay_index)
  if not overlay then return false end
  if self._overlay_player ~= local_player or self._saved_overlay_weight == nil then
    self._overlay_player = local_player
    self._saved_overlay_weight = tonumber(overlay.weight)
  end
  overlay.weight = math.max(0, math.min(1, tonumber(weight) or 0))
  return true
end,
_restore_anim_overlay = function(self, local_player)
  local target = local_player or self._overlay_player
  if not target or self._saved_overlay_weight == nil then return end
  local success, self_index = pcall(c_entity.new, target)
  if success and self_index then
    local overlay = self_index:get_anim_overlay(12)
    if overlay then overlay.weight = math.max(0, math.min(1, self._saved_overlay_weight)) end
  end
  self._saved_overlay_weight = nil
  self._overlay_player = nil
end,
_reset_ground_state = function(self, local_player)
  self._ground_jitter_phase = nil
  self._ground_jitter_delay = nil
  self._ground_jitter_value = nil
  if local_player then
    self:_restore_pose_parameter(local_player, 0)
    if self._ground_moonwalk_active then
      self:_restore_pose_parameter(local_player, 1)
      self:_restore_pose_parameter(local_player, 7)
    end
  end
  self._ground_moonwalk_active = false
end,
_reset_air_state = function(self, local_player)
  self._air_pose_target = nil
  if local_player then
    self:_restore_pose_parameter(local_player, 6)
    self:_set_air_walking(local_player, false)
  end
end,
_restore_animation_state = function(self, local_player)
  local target = local_player or self._anim_player
  if target then
    self:_restore_pose_parameter(target, 0)
    self:_restore_pose_parameter(target, 1)
    self:_restore_pose_parameter(target, 6)
    self:_restore_pose_parameter(target, 7)
    self:_set_air_walking(target, false)
    self:_restore_anim_overlay(target)
  end
  self._ground_jitter_phase = nil
  self._ground_jitter_delay = nil
  self._ground_jitter_value = nil
  self._ground_moonwalk_active = false
  self._air_pose_target = nil
  self._earthshake_tick = nil
  self._earthshake_weight = nil
end,
_custom_legs_movement_active = function(self)
  local animation_breaker = Class.ui.menu.misc_tab and Class.ui.menu.misc_tab.animation_breaker
  if not animation_breaker or not animation_breaker.other then return false end
  local active = false
  pcall(function()
    active = animation_breaker.enabled:get() == true
      and self:_multi_has(animation_breaker.triggers, "Other")
      and self:_multi_has(animation_breaker.other.mode, "Leg movement")
  end)
  return active
end,
_sync_legs_movement = function(self, force_restore)
  local animation_breaker = Class.ui.menu.misc_tab and Class.ui.menu.misc_tab.animation_breaker
  local legs_ref = Class.util.reference.aa_legs_movement
  if not legs_ref or not legs_ref[1] then return end

  local local_player = entity.get_local_player()
  local alive = local_player ~= nil and entity.is_alive(local_player)
  local on_ground = false
  if alive then
    local flags = entity.get_prop(local_player, "m_fFlags") or 0
    on_ground = bit.band(flags, 1) == 1
  end

  local ground_override, custom_override, custom_value, ground_mode = false, false, nil, "Default"
  pcall(function()
    local enabled = animation_breaker and animation_breaker.enabled:get() == true
    if animation_breaker and animation_breaker.ground and animation_breaker.ground.mode then
      ground_mode = animation_breaker.ground.mode:get()
    end
    ground_override = not force_restore and alive and enabled and on_ground
      and self:_multi_has(animation_breaker.triggers, "Legs")
      and ground_mode ~= "Default"
    custom_override = not force_restore and alive and enabled and self:_custom_legs_movement_active()
    if custom_override then custom_value = animation_breaker.other.leg_movement:get() end
  end)

  if ground_override or custom_override then
    if not self._legs_movement_saved then
      local ok, value = pcall(ui.get, legs_ref[1])
      if ok and value ~= nil then
        self._saved_legs_movement = value
        self._legs_movement_saved = true
      end
    end
    local ground_value = ground_mode == "Moonwalk" and "Never slide" or "Always slide"
    local desired = custom_override and custom_value or (ground_override and ground_value)
    if desired ~= nil then pcall(ui.set, legs_ref[1], desired) end
    return
  end

  if self._legs_movement_saved then
    pcall(ui.set, legs_ref[1], self._saved_legs_movement)
    self._saved_legs_movement = nil
    self._legs_movement_saved = false
  end
end,
_ground_animations = function(self, cmd, velocity)
  local animation_breaker = Class.ui.menu.misc_tab.animation_breaker
  local local_player = entity.get_local_player()
  if not local_player then return end
  local breaker_mode = animation_breaker.ground.mode:get()
  local target = 0

  if breaker_mode == "Moonwalk" then
    self._ground_jitter_phase = nil
    self._ground_jitter_delay = nil
    self._ground_jitter_value = nil
    self:_restore_pose_parameter(local_player, 0)
    self:_set_pose_parameter(local_player, 0, 1)
    self:_set_pose_parameter(local_player, 1, 7)
    self._ground_moonwalk_active = true
    return
  else
    if self._ground_moonwalk_active then
      self:_restore_pose_parameter(local_player, 1)
      self:_restore_pose_parameter(local_player, 7)
      self._ground_moonwalk_active = false
    end
  end

  if breaker_mode == "Static" then
    local delta = tonumber(animation_breaker.ground.static_delta:get()) or 0
    target = math.max(0, math.min(100, delta)) / 100
    self._ground_jitter_phase = nil
    self._ground_jitter_delay = nil
    self._ground_jitter_value = nil
  elseif breaker_mode == "Jitter" then
    local delta_from = tonumber(animation_breaker.ground.delta_from:get()) or 0
    local delta_to = tonumber(animation_breaker.ground.delta_to:get()) or 100
    delta_from = math.max(0, math.min(100, delta_from))
    delta_to = math.max(0, math.min(100, delta_to))
    if delta_from > delta_to then delta_from, delta_to = delta_to, delta_from end

    local delay = math.floor(tonumber(animation_breaker.ground.jitter_delay:get()) or 2)
    delay = math.max(1, math.min(32, delay))
    if self._ground_jitter_delay ~= delay then
      self._ground_jitter_delay = delay
      self._ground_jitter_phase = nil
      self._ground_jitter_value = nil
    end

    local tick = tonumber(globals.tickcount()) or 0
    local phase = math.floor(tick / delay) % 2
    if self._ground_jitter_phase ~= phase or self._ground_jitter_value == nil then
      self._ground_jitter_phase = phase
      -- Alternate between a neutral pose value and a randomized leg value.
      self._ground_jitter_value = phase == 0
        and 0
        or client.random_float(delta_from / 100, delta_to / 100)
    end
    target = self._ground_jitter_value
  end

  self:_set_pose_parameter(local_player, target, 0)
end,
_air_animations = function(self)
  local animation_breaker = Class.ui.menu.misc_tab.animation_breaker
  local local_player = entity.get_local_player()
  if not local_player then return end
  local breaker_mode = animation_breaker.air.mode:get()
  local target = 0

  if breaker_mode == "Static" then
    target = 0.25
    self:_set_air_walking(local_player, false)
  elseif breaker_mode == "Allah" then
    target = 0
    self:_set_air_walking(local_player, true)
  elseif breaker_mode == "Kangaroo" then
    self:_set_air_walking(local_player, false)
    local intensity = 0.25
    local floor = 0.05 + (0.18 * intensity)
    local ceiling = 0.18 + (0.82 * intensity)
    target = client.random_float(floor, ceiling)
    if (tonumber(globals.tickcount()) or 0) % 3 == 0 then
      target = math.min(1, target + (0.12 * intensity))
    end
  else
    self:_set_air_walking(local_player, false)
  end

  if self._air_pose_target == nil then
    self._air_pose_target = target
  else
    local smoothing = breaker_mode == "Kangaroo" and 0.45 or 0.75
    self._air_pose_target = self._air_pose_target + ((target - self._air_pose_target) * smoothing)
  end
  if math.abs(self._air_pose_target) < 0.001 then self._air_pose_target = 0 end
  self:_set_pose_parameter(local_player, self._air_pose_target, 6)
end,
_multi_has = function(self, el, name)
  if not el then return false end
  local success, value = pcall(function() return el:get(name) end)
  if success and value == true then return true end
  local ok, values = pcall(function() return el:get() end)
  if ok then
    if type(values) == "table" then
      for index = 1, #values do
        if values[index] == name then return true end
      end
      if values[name] then return true end
    elseif values == name then
      return true
    end
  end
  return false
end,
_extra_animations = function(self, cmd, velocity)
  local animation_breaker = Class.ui.menu.misc_tab.animation_breaker
  local local_player = entity.get_local_player()
  if not animation_breaker or not local_player or not animation_breaker.triggers
    or not self:_multi_has(animation_breaker.triggers, "Other") then
    self:_restore_anim_overlay(local_player)
    return
  end

  local options = animation_breaker.other
  if not options or not options.mode then
    self:_restore_anim_overlay(local_player)
    return
  end

  local overlay_weight = 0
  local has_overlay_effect = false
  local selected_body_lean = self:_multi_has(options.mode, "Body Lean")
  local selected_earthshake = self:_multi_has(options.mode, "Earthshake")

  if selected_body_lean then
    local allow_standing = false
    pcall(function()
      allow_standing = options.allow_standing_leaning and options.allow_standing_leaning:get() == true
    end)
    local lean = 0
    pcall(function() lean = tonumber(options.body_lean:get()) or 0 end)
    lean = math.max(0, math.min(100, lean)) / 100
    if lean > 0 and (allow_standing or (tonumber(velocity) or 0) > 5) then
      overlay_weight = lean
      has_overlay_effect = true
    end
  end

  if selected_earthshake then
    local strength = 100
    pcall(function() strength = tonumber(options.earthshake_strength:get()) or 100 end)
    strength = math.max(1, math.min(100, strength))
    local in_air = false
    local flags = entity.get_prop(local_player, "m_fFlags") or 0
    in_air = bit.band(flags, 1) == 0
    if strength >= 100 or not in_air then
      local tick = tonumber(globals.tickcount()) or 0
      if self._earthshake_tick ~= tick then
        local min_weight = 0.05 + (strength / 100) * 0.15
        local max_weight = 0.15 + (strength / 100) * 0.85
        self._earthshake_weight = client.random_float(min_weight, max_weight)
        self._earthshake_tick = tick
      end
      local earth_weight = tonumber(self._earthshake_weight) or 0
      if has_overlay_effect then
        overlay_weight = 1 - ((1 - overlay_weight) * (1 - earth_weight))
      else
        overlay_weight = earth_weight
      end
      has_overlay_effect = true
    end
  end

  if has_overlay_effect then
    self:_update_anim_overlay(12, overlay_weight)
  else
    self:_restore_anim_overlay(local_player)
  end

  if options.walking_legs and options.walking_legs:get() and cmd then
    local peek = Class.util.reference.rage_peek_assist
    local peek_on = false
    if peek and peek[2] then pcall(function() peek_on = ui.get(peek[2]) == true end) end
    if peek_on and entity.get_prop(local_player, "m_MoveType") == 2 then
      local command_number = cmd.command_number
      local command = self:_ffi_helper(command_number)
      if command then
        pcall(function()
          command.buttons = bit.band(command.buttons, bit.bnot(8))
          command.buttons = bit.band(command.buttons, bit.bnot(16))
          command.buttons = bit.band(command.buttons, bit.bnot(512))
          command.buttons = bit.band(command.buttons, bit.bnot(1024))
        end)
      end
    end
  end
end,
update = function(self, cmd)
  local animation_breaker = Class.ui.menu.misc_tab and Class.ui.menu.misc_tab.animation_breaker
  local local_player = entity.get_local_player()
  local alive = local_player ~= nil and entity.is_alive(local_player)
  local enabled = animation_breaker and animation_breaker.enabled and animation_breaker.enabled:get() == true

  self:_prepare_anim_player(local_player)
  self:_sync_legs_movement(not (enabled and alive))
  if not enabled or not alive then
    self:_restore_animation_state(local_player)
    return
  end

  local flags = entity.get_prop(local_player, "m_fFlags") or 0
  local in_air = bit.band(flags, 1) == 0
  local vx = tonumber(entity.get_prop(local_player, "m_vecVelocity[0]")) or 0
  local vy = tonumber(entity.get_prop(local_player, "m_vecVelocity[1]")) or 0
  local velocity = math.sqrt((vx * vx) + (vy * vy))
  local has_legs = self:_multi_has(animation_breaker.triggers, "Legs")
  local has_air = self:_multi_has(animation_breaker.triggers, "Air")
  local has_other = self:_multi_has(animation_breaker.triggers, "Other")

  if not in_air then
    self:_reset_air_state(local_player)
  end

  if has_legs and not in_air then
    self:_ground_animations(cmd, velocity)
  else
    self:_reset_ground_state(local_player)
  end

  if has_air and in_air then
    self:_air_animations()
  elseif in_air then
    self:_reset_air_state(local_player)
  end

  if has_other then
    self:_extra_animations(cmd, velocity)
  else
    self:_restore_anim_overlay(local_player)
  end
end,

on_post_update_clientside_animation = function(self)
  local animation_breaker = Class.ui.menu.misc_tab and Class.ui.menu.misc_tab.animation_breaker
  local local_player = entity.get_local_player()
  local alive = animation_breaker and animation_breaker.enabled
    and animation_breaker.enabled:get() == true
    and local_player ~= nil and entity.is_alive(local_player)

  local air_walking = false
  if alive and animation_breaker.air and animation_breaker.air.mode then
    local flags = entity.get_prop(local_player, "m_fFlags") or 0
    local in_air = bit.band(flags, 1) == 0
    air_walking = in_air
      and self:_multi_has(animation_breaker.triggers, "Air")
      and animation_breaker.air.mode:get() == "Allah"
  end
  self:_set_air_walking(local_player, air_walking)

  if alive then
    local flags = entity.get_prop(local_player, "m_fFlags") or 0
    local on_ground = bit.band(flags, 1) == 1
    local ground_mode = animation_breaker.ground and animation_breaker.ground.mode
      and animation_breaker.ground.mode:get() or "Default"
    if on_ground and self:_multi_has(animation_breaker.triggers, "Legs")
      and ground_mode == "Moonwalk" then
      self:_set_pose_parameter(local_player, 0, 1)
      self:_set_pose_parameter(local_player, 1, 7)
    end
  end

  if not alive or not self:_multi_has(animation_breaker.triggers, "Other") then
    self:_restore_anim_overlay(local_player)
    return
  end
  local vx = tonumber(entity.get_prop(local_player, "m_vecVelocity[0]")) or 0
  local vy = tonumber(entity.get_prop(local_player, "m_vecVelocity[1]")) or 0
  self:_extra_animations(nil, math.sqrt((vx * vx) + (vy * vy)))
end,

}
}

-- Restore the debug overlay after rebuilding the visuals table.

do
  local animation_breaker = Class.ui.menu.misc_tab.animation_breaker
  local function sync_custom_legs_movement()
    pcall(function()
      Class.visuals.animation_breaker:_sync_legs_movement()
    end)
  end
  local controls = {
    animation_breaker.enabled,
    animation_breaker.triggers,
    animation_breaker.other.mode,
    animation_breaker.other.leg_movement,
  }
  for index = 1, #controls do
    local control = controls[index]
    if control and control.set_callback then
      pcall(control.set_callback, control, sync_custom_legs_movement)
    end
  end
  sync_custom_legs_movement()
end

Class.misc.console_enhancement = {
 console_cleaner = {
  on_level_init = function(self)
    local addons = Class.ui.menu.misc_tab.console_enhancement
    local mode = addons and addons.mode
    if not mode then return end
    local selected = mode:get()
    if selected ~= "Clean On Level Init" then return end
    client.exec("clear")
  end
 },
console_filter = {
 _toggle = function(self)
   local addons = Class.ui.menu.misc_tab.console_enhancement
   local mode = addons and addons.mode
   if not mode then return end
   local selected = mode:get()
   if selected ~= "Console Filter" then
     Class.util:reset_console_filter()
     return
   end
   Class.util:setup_console_filter()
 end,
 setup = function(self)
   local addons = Class.ui.menu.misc_tab.console_enhancement
   local mode = addons and addons.mode
   if not mode then return end
   mode:set_callback(function()
     self:_toggle()
   end)
   self:_toggle()
 end
}
}
Class.misc.notifications_ui = {
 should_show = function(self, trigger)
   local success, show = pcall(function()
     if trigger == "Anti-Bruteforce" then
       local anti_bruteforce = Class.ui.menu.antiaim_tab.additional.fakelag.anti_bruteforce
       return anti_bruteforce and anti_bruteforce.enabled:get()
         and anti_bruteforce.notify
         and anti_bruteforce.notify:get("On Screen") == true
     end
     if trigger == "Connection problems" then
       local logger = Class.ui.menu.misc_tab.event_logger
       return logger and logger.enabled:get() and logger.triggers
         and logger.triggers.event_triggers:get("Connection problems") == true
         and logger.triggers.event_triggers:get("On Screen") == true
     end
     local logger = Class.ui.menu.misc_tab.event_logger
     if not logger or not logger.enabled:get() or not logger.triggers then return false end
     return logger.triggers.event_triggers:get("On Screen") == true
   end)
   return success and show == true
 end,
}
do
  local chat     = require("gamesense/chat")
  local localize = require("gamesense/localize")
  local gs_api   = panorama.open().GameStateAPI
  local last_say = {}
  Class.misc.enemy_chat_viewer = {
   on_player_say = function(self, e)
     if not addon_enabled("Enemy Chat Viewer") then return end
     local ent = client.userid_to_entindex(e.userid)
     if not ent or ent == 0 then return end
     if not entity.is_enemy(ent) then return end
     local xuid = gs_api.GetPlayerXuidStringFromEntIndex(ent)
     if gs_api.IsSelectedPlayerMuted(xuid) then return end
     if cvar.cl_mute_enemy_team and cvar.cl_mute_enemy_team:get_int() == 1 then return end
     if cvar.cl_mute_all_but_friends_and_party and cvar.cl_mute_all_but_friends_and_party:get_int() == 1 then return end
     client.delay_call(0.2, function()
       local current_time = globals.realtime()
       if last_say[ent] and math.abs(current_time - last_say[ent]) < 0.4 then return end
       local res = entity.get_player_resource()
       local team_id = res and entity.get_prop(res, "m_iTeam", ent)
       local side = (team_id == 2) and "T" or "CT"
       local location = entity.get_prop(ent, "m_szLastPlaceName") or ""
       local name = entity.get_player_name(ent) or "?"
       local alive = entity.is_alive(ent)
       local loc_key = "Cstrike_Chat_" .. side .. "_" .. (alive and "Loc" or "Dead")
       local loc_name = (location ~= "") and location or "UI_Unknown"
       local formatted = localize(loc_key, {
        s1 = name,
        s2 = e.text,
        s3 = localize(loc_name),
       })
      chat.print_player(ent, formatted)
    end)
  end,
  on_player_chat = function(self, e)
    if e and e.entity then
      last_say[e.entity] = globals.realtime()
    end
  end,
  }
end
do
  local PREFIX = "afterglow_"
  -- GameSense file paths are relative to the CS:GO game directory.
  -- Store presets directly beside the game's Lua scripts, not in cfg/ or a subfolder.
  local PRESETS_FILE = "afterglow_presets.db"
  local LEGACY_PRESETS_FILES = {
    "cfg/afterglow_presets.db",
    "afterglow/afterglow_presets.db",
    "gothsense_presets.gsc",
  }

  local function ensure_storage_directory()
    -- The game root already exists; no directory needs to be created.
    return true
  end

  local UI_AUTOSAVE_KEYS = {
   menu = "afterglow.ui.autosave.menu.v1",
   states_t = "afterglow.ui.autosave.states_t.v2",
   states_ct = "afterglow.ui.autosave.states_ct.v2",
   freestanding = "afterglow.ui.autosave.freestanding.v1",
  }
  local UI_AUTOSAVE_KEYS_LEGACY = {
   menu = "gothsense.ui.autosave.menu.v1",
   states_t = "afterglow.ui.autosave.states_t.v1",
   states_ct = "afterglow.ui.autosave.states_ct.v1",
   freestanding = "gothsense.ui.autosave.freestanding.v2",
  }
  local UI_AUTOSAVE_PACKAGES = {
   { UI_AUTOSAVE_KEYS.menu, "package" },
   { UI_AUTOSAVE_KEYS.states_t, "package_t" },
   { UI_AUTOSAVE_KEYS.states_ct, "package_ct" },
   { UI_AUTOSAVE_KEYS.freestanding, "package_fs" },
  }
  local COMPACT_MAP = {
   "menu.visuals_tab.interface.", "menu.visuals_tab.other.", "menu.antiaim_tab.additional.",
   "menu.gamesense_settings.", "menu.misc_tab.", "menu.antiaim_tab.builder.", "states_t.", "states_ct.",
   "yaw.modifier.ways_offsets.", "yaw.delay.custom.delays.", "yaw.modifier.", "yaw.delay.",
   "body_yaw.", "force_defensive", "variability_value", "right_value",
   "left_value", "custom.delays.", "ways_offsets.", "override_state", "states_"
  }
local function cfg_log(config_name, action, is_error)
  pcall(play_state_action_sound, not is_error)
  local name = tostring(config_name or "")
  action = tostring(action or "")

  local action_text = {
    ["empty name"] = "name is empty",
    ["already exists"] = "already exists",
    ["no data"] = "no data to save",
    ["write failed"] = "write failed",
    ["no preset"] = "no preset selected",
    ["select sections"] = "select at least one section to load",
    ["invalid data"] = "invalid config data",
    ["apply failed"] = "could not apply config",
    ["encode failed"] = "could not export config",
    ["clipboard failed"] = "clipboard export failed",
    ["clipboard read failed"] = "clipboard read failed",
    ["empty clipboard"] = "clipboard is empty",
    ["invalid format"] = "invalid config format",
    ["created"] = "created",
    ["saved"] = "saved",
    ["loaded"] = "loaded",
    ["deleted"] = "deleted",
    ["exported"] = "exported to clipboard",
    ["imported"] = "imported from clipboard",
    ["cloud setup required"] = "cloud endpoint or key is missing",
    ["cloud connection failed"] = "cloud connection failed",
    ["cloud response invalid"] = "invalid cloud response",
    ["cloud synced"] = "cloud list refreshed",
    ["cloud created"] = "created in cloud",
    ["cloud saved"] = "saved to cloud",
    ["cloud loaded"] = "loaded from cloud",
    ["cloud deleted"] = "deleted from cloud",
    ["cloud name exists"] = "name already exists in cloud",
    ["cloud key copied"] = "cloud key copied",
    ["not your config"] = "not your config",
    ["select a public config"] = "select a public config",
  }
  action = action_text[action] or action

  -- Config actions always go to the console. When Event Logger is enabled,
  -- reuse its live prefix and success/error color pickers; otherwise use the
  -- built-in afterglow prefix and default colors.
  local white = {240, 240, 240}
  local accent = is_error and {225, 80, 80} or {255, 255, 255}
  local prefix_raw = "nb"
  local logger_enabled = false
  local logger = nil
  pcall(function()
    logger = Class.ui.menu.misc_tab.event_logger
    logger_enabled = logger ~= nil and logger.enabled ~= nil and logger.enabled:get() == true
  end)

  if logger_enabled then
    pcall(function() prefix_raw = tostring(logger.prefix:get() or "") end)
    local color_field = is_error and "miss_connection_color" or "hit_purchase_color"
    if Class.misc and Class.misc.event_logger and Class.misc.event_logger._get_color then
      local fallback = is_error and {225, 80, 80} or {255, 255, 255}
      local ok, color = pcall(Class.misc.event_logger._get_color, Class.misc.event_logger, color_field, fallback)
      if ok and type(color) == "table" then
        accent = {tonumber(color[1]) or fallback[1], tonumber(color[2]) or fallback[2], tonumber(color[3]) or fallback[3]}
      end
    end
  end

  local output = {}
  local prefix_ok, prefix = pcall(Class.util.format_log_prefix, Class.util, prefix_raw, accent, white, accent)
  if prefix_ok and type(prefix) == "table" then
    for index = 1, #prefix do output[#output + 1] = prefix[index] end
  end
  output[#output + 1] = {text = "Config ", color = white}
  if name ~= "" then
    output[#output + 1] = {text = name, color = accent}
    output[#output + 1] = {text = " ", color = white}
  end
  output[#output + 1] = {text = action .. "\n", color = accent}

  pcall(function()
    Class.util.output_message(output)
  end)
end

Class.config.db = Class.config.db or { config_presets = {}, config_data_local = {} }
do
  local TEXT_DB_KEY = "afterglow.texts"
  local TEXT_DB_KEY_LEGACY = "G0TH$EH$E.texts"
  local PREFIX_DB_KEY = "afterglow.event_logger.prefix.v1"
  local DEFAULTS = {
   manual_left = "左",
   manual_right = "右",
   manual_forward = "前",
  }
  local function exact_string(value)
    if value == nil then return "" end
    return tostring(value)
  end
  Class.util.text_state = {
   _applying = false,
   _bound = false,
   get = function(self)
     local menu = Class.ui.menu
     local d = {}
     local logger = menu.misc_tab.event_logger
     d.event_logger_prefix = exact_string(logger.prefix:get())
     local ma = menu.visuals_tab.interface.manual_arrows
     if ma then
      d.manual_left = exact_string(ma.left and ma.left:get())
      d.manual_right = exact_string(ma.right and ma.right:get())
      d.manual_forward = exact_string(ma.forward and ma.forward:get())
     end
     local watermark = menu.visuals_tab.other.watermark
     if watermark and watermark.text then
      d.watermark_text = exact_string(watermark.text:get())
     end
     return d
   end,
   apply = function(self, d)
     local menu = Class.ui.menu
     if not menu then return end
     d = type(d) == "table" and d or {}
     self._applying = true
     if d.event_logger_prefix ~= nil then
      menu.misc_tab.event_logger.prefix:set(exact_string(d.event_logger_prefix))
     end
     local ma = menu.visuals_tab.interface.manual_arrows
     if ma then
      if ma.left then ma.left:set(exact_string(d.manual_left ~= nil and d.manual_left or DEFAULTS.manual_left)) end
      if ma.right then ma.right:set(exact_string(d.manual_right ~= nil and d.manual_right or DEFAULTS.manual_right)) end
      if ma.forward then ma.forward:set(exact_string(d.manual_forward ~= nil and d.manual_forward or DEFAULTS.manual_forward)) end
     end
     local watermark = menu.visuals_tab.other.watermark
     if watermark and watermark.text and d.watermark_text ~= nil then
      watermark.text:set(exact_string(d.watermark_text))
     end
     self._applying = false
   end,
   save = function(self)
    if self._applying or not database or not database.write then return end
    local d = self:get()
    pcall(database.write, TEXT_DB_KEY, d)
    pcall(database.write, PREFIX_DB_KEY, d.event_logger_prefix)
   end,
   load = function(self)
    local d = nil
    if database and database.read then
     local success, stored = pcall(database.read, TEXT_DB_KEY)
     if success and type(stored) == "table" then
      d = stored
     else
      local legacy_ok, legacy = pcall(database.read, TEXT_DB_KEY_LEGACY)
      if legacy_ok and type(legacy) == "table" then
       d = legacy
       pcall(database.write, TEXT_DB_KEY, legacy)
      end
     end
     local prefix_ok, saved_prefix = pcall(database.read, PREFIX_DB_KEY)
     if prefix_ok and saved_prefix ~= nil then
      d = type(d) == "table" and d or {}
      d.event_logger_prefix = exact_string(saved_prefix)
     end
    end
    self:apply(d or {})
   end,
   bind = function(self)
    if self._bound then return end
    local menu = Class.ui.menu
    if not menu then return end
    local function changed()
     if not self._applying then self:save() end
    end
    menu.misc_tab.event_logger.prefix:set_callback(changed)
    local ma = menu.visuals_tab.interface.manual_arrows
    if ma then
     if ma.left then ma.left:set_callback(changed) end
     if ma.right then ma.right:set_callback(changed) end
     if ma.forward then ma.forward:set_callback(changed) end
    end
    local watermark = menu.visuals_tab.other.watermark
    if watermark and watermark.text then watermark.text:set_callback(changed) end
    self._bound = true
   end,
  }
end
function Class.config:_save_ui_autosave()
  if self._ui_autosave_busy then return end
  self._ui_autosave_busy = true
  for i = 1, #UI_AUTOSAVE_PACKAGES do
    local entry = UI_AUTOSAVE_PACKAGES[i]
    local package = self[entry[2]]
    if package and package.save then
      local ok, blob = pcall(package.save, package)
      if ok and type(blob) == "string" and #blob > 0 then
        pcall(database.write, entry[1], blob)
      end
    end
  end
  self._ui_autosave_busy = false
end
function Class.config:_restore_ui_autosave()
  local legacy_states_loaded = { states_t = false, states_ct = false }
  for i = 1, #UI_AUTOSAVE_PACKAGES do
    local entry = UI_AUTOSAVE_PACKAGES[i]
    local package = self[entry[2]]
    if package and package.load then
      local ok, blob = pcall(database.read, entry[1])
      if not ok or type(blob) ~= "string" or #blob == 0 then
        local legacy_keys = {}
        for k, v in pairs(UI_AUTOSAVE_KEYS) do
          if v == entry[1] then
            legacy_keys[#legacy_keys + 1] = UI_AUTOSAVE_KEYS_LEGACY[k]
            if k == "states_t" then legacy_keys[#legacy_keys + 1] = "gothsense.ui.autosave.states_t.v1" end
            if k == "states_ct" then legacy_keys[#legacy_keys + 1] = "gothsense.ui.autosave.states_ct.v1" end
            break
          end
        end
        for legacy_index = 1, #legacy_keys do
          local legacy_key = legacy_keys[legacy_index]
          if legacy_key then
            ok, blob = pcall(database.read, legacy_key)
            if ok and type(blob) == "string" and #blob > 0 then
              pcall(database.write, entry[1], blob)
              break
            end
          end
        end
      end
      if ok and type(blob) == "string" and #blob > 0 then
        local load_ok, load_result = pcall(package.load, package, blob)
        if load_ok and load_result ~= false then
          if entry[2] == "package_t" then legacy_states_loaded.states_t = true end
          if entry[2] == "package_ct" then legacy_states_loaded.states_ct = true end
        end
      end
    end
  end

  local migration_key = "afterglow.ui.ways_count_migrated.v1"
  local migration_ok, migration_done = pcall(database.read, migration_key)
  if not migration_ok or migration_done ~= true then
    local legacy_ways = { [1] = 3, [2] = 5, [3] = 7, [4] = 9 }
    local function migrate_saved_team(team_key, states, package)
      if not legacy_states_loaded[team_key] or type(states) ~= "table" then return end
      for index = 1, #states do
        local ways = states[index] and states[index].yaw and states[index].yaw.modifier and states[index].yaw.modifier.ways
        if ways and ways.get and ways.set then
          local old_value = tonumber(ways:get())
          if legacy_ways[old_value] then ways:set(legacy_ways[old_value]) end
        end
      end
      if package and package.save then
        local ok, saved = pcall(package.save, package)
        if ok and type(saved) == "string" and #saved > 0 then
          pcall(database.write, UI_AUTOSAVE_KEYS[team_key], saved)
        end
      end
    end
    migrate_saved_team("states_t", Class.ui.antiaim_conditions_t, self.package_t)
    migrate_saved_team("states_ct", Class.ui.antiaim_conditions_ct, self.package_ct)
    pcall(database.write, migration_key, true)
  end
end
function Class.config:_read_file()
  self.db.config_presets = self.db.config_presets or {}
  self.db.config_data_local = self.db.config_data_local or {}
  ensure_storage_directory()

  local raw_config, loaded_legacy = nil, false
  local ok, stored_config = pcall(readfile, PRESETS_FILE)
  if ok and type(stored_config) == "string" and #stored_config > 0 then
    raw_config = stored_config
  else
    -- Migrate presets from earlier storage locations into the game root.
    for index = 1, #LEGACY_PRESETS_FILES do
      local legacy_ok, legacy_config = pcall(readfile, LEGACY_PRESETS_FILES[index])
      if legacy_ok and type(legacy_config) == "string" and #legacy_config > 0 then
        raw_config = legacy_config
        loaded_legacy = true
        break
      end
    end
  end

  if not raw_config then
    self:_write_file()
    return
  end

  if type(raw_config) == "string" and #raw_config > 0 then
    local config_presets, config_data_local, seen = {}, {}, {}
    for config_line in raw_config:gmatch("[^\r\n]+") do
      if config_line:sub(1, 1) ~= "#" and config_line ~= "" then
        local kind, config_name_local, config_payload = config_line:match("^(%w+)|([^|]+)|(.*)$")
        if (kind == "P" or kind == "D") and config_name_local and config_name_local ~= "" then
          if not seen[config_name_local] then
            config_presets[#config_presets + 1] = config_name_local
            seen[config_name_local] = true
          end
          if config_payload and config_payload ~= "" then
            config_data_local[config_name_local] = config_payload
          end
        end
      end
    end
    if #config_presets > 0 or next(config_data_local) then
      self.db.config_presets = config_presets
      self.db.config_data_local = config_data_local
      if loaded_legacy then
        self:_write_file()
      end
      return
    end
  end
end
function Class.config:_write_file()
  ensure_storage_directory()
  local lines = { "# afterglow_presets.db — script configs (not GS cfg)" }
  local config_presets = self.db.config_presets or {}
  local config_data_local = self.db.config_data_local or {}
  local listed_names = {}
  for index = 1, #config_presets do
    local config_name_local = config_presets[index]
    if type(config_name_local) == "string" and config_name_local ~= "" then
      listed_names[config_name_local] = true
      local config_payload = config_data_local[config_name_local]
      if type(config_payload) == "table" then
        config_payload = self:_encode(config_payload) or ""
      end
      lines[#lines + 1] = string.format("P|%s|%s", config_name_local, tostring(config_payload or ""))
    end
  end
  for config_name_local, config_payload in pairs(config_data_local) do
    if type(config_name_local) == "string" and not listed_names[config_name_local] then
      if type(config_payload) == "table" then
        config_payload = self:_encode(config_payload) or ""
      end
      lines[#lines + 1] = string.format("D|%s|%s", config_name_local, tostring(config_payload or ""))
    end
  end
  local body = table.concat(lines, "\n")
  local success = pcall(writefile, PRESETS_FILE, body)
  if not success then return false end

  -- Verify the write instead of treating a successful pcall as proof that the file exists.
  local verify_ok, written = pcall(readfile, PRESETS_FILE)
  return verify_ok and type(written) == "string" and written == body
end
local function format_cloud_created_at(value)
  local timestamp = tonumber(value)
  if not timestamp or timestamp <= 0 then return "--" end

  if timestamp > 100000000000000 then
    timestamp = math.floor(timestamp / 1000000)
  elseif timestamp > 100000000000 then
    timestamp = math.floor(timestamp / 1000)
  end
  timestamp = math.floor(timestamp)

  if os and type(os.date) == "function" then
    local ok, formatted = pcall(function()
      return os.date("%d.%m.%Y", timestamp)
    end)
    if ok and type(formatted) == "string" and formatted ~= "" then
      return formatted
    end
  end

  local days = math.floor(timestamp / 86400)
  local z = days + 719468
  local era = math.floor(z / 146097)
  local doe = z - era * 146097
  local yoe = math.floor((doe - math.floor(doe / 1460) + math.floor(doe / 36524) - math.floor(doe / 146096)) / 365)
  local year = yoe + era * 400
  local doy = doe - (365 * yoe + math.floor(yoe / 4) - math.floor(yoe / 100))
  local mp = math.floor((5 * doy + 2) / 153)
  local day = doy - math.floor((153 * mp + 2) / 5) + 1
  local month = mp + (mp < 10 and 3 or -9)
  year = year + (month <= 2 and 1 or 0)

  return string.format("%02d.%02d.%04d", day, month, year)
end

local function crop_cloud_text(value, max_bytes)
  value = tostring(value or "")
  if #value <= max_bytes then return value end
  if max_bytes <= 1 then return value:sub(1, max_bytes) end

  local prefix = value:sub(1, max_bytes - 1)
  local index = #prefix
  while index > 0 do
    local byte = prefix:byte(index)
    if byte < 128 or byte >= 192 then break end
    index = index - 1
  end
  if index > 0 then
    local lead = prefix:byte(index)
    local expected = lead >= 240 and 4 or (lead >= 224 and 3 or (lead >= 192 and 2 or 1))
    if expected > 1 and (#prefix - index + 1) < expected then
      prefix = prefix:sub(1, index - 1)
    end
  end
  return prefix .. "~"
end

local function cloud_list_display_name(name, metadata)
  metadata = type(metadata) == "table" and metadata or {}
  local username = tostring(metadata.username or "user"):gsub("[%c]", ""):gsub("^%s+", ""):gsub("%s+$", "")
  if username == "" then username = "user" end
  username = crop_cloud_text(username, 12)

  -- Keep list rows compact: favorite glyph + config name on the left, author on the right.
  -- The current user's vote highlights the config name: olive for like, muted red for dislike.
  local favorite_mark = metadata.is_favorite and ("\xEE\x87\xB8 ") or ""
  local favorite_accent = tostring(pui.accent or "B4B465FF")
  local favorite_display = favorite_mark ~= "" and ("\a" .. favorite_accent .. favorite_mark .. "\r") or ""
  local vote = tonumber(metadata.my_vote) or 0
  local name_color = vote > 0 and "\aB4B465FF" or (vote < 0 and "\aC97878FF" or "\aFFFFFFFF")
  local right = " ~" .. username
  local row_width = 52
  local name_width = math.max(7, row_width - #right - #favorite_mark - 1)
  local left = crop_cloud_text(name, name_width)
  return favorite_display .. name_color .. left .. "\r\aA0A0A0FF" .. right .. "\r"
end

function Class.config:_update_cloud_info()
  local controls = Class.ui.menu and Class.ui.menu.config_tab
  local label = controls and controls.cloud_info
  if not label or type(label.set) ~= "function" then return end

  local item = self:_selected_cloud_item()
  if not item then
    pcall(label.set, label, "\aA0A0A0FFSelect a cloud config\r")
    return
  end

  local created = format_cloud_created_at(item.created_at)
  local info = "\aA0A0A0FFDate ~ " .. created
  if item.is_owner then
    info = "\aB4B465FFYour config  \r" .. info
  end
  if item.kind == "public" then
    -- One neutral E19D marker groups both public-config vote counters.
    local metric_glyph = "\xEE\x86\x9D"
    info = info .. "     \a8FA7B0FF" .. metric_glyph
      .. " \aB4B465FF+" .. tostring(tonumber(item.likes) or 0)
      .. "\r / \aC97878FF-" .. tostring(tonumber(item.dislikes) or 0)
  end
  pcall(label.set, label, info .. "\r")
end

function Class.config:_selected_cloud_item()
  if not self:_is_cloud_selected() then return nil end
  local element = Class.ui.menu and Class.ui.menu.config_tab
  if not element or not element.list then return nil end
  local index = 0
  local ok, value = pcall(element.list.get, element.list)
  if ok then index = tonumber(value) or 0 end
  return self.cloud_visible_items and self.cloud_visible_items[index + 1] or nil
end

function Class.config:_refresh_list(prefer_name)
  local element = Class.ui.menu and Class.ui.menu.config_tab
  if not element or not element.list then return end

  local keep = prefer_name
  if not keep and self:_is_cloud_selected() then
    local selected = self:_selected_cloud_item()
    keep = selected and selected.key or nil
  elseif not keep then
    keep = self:_selected_name()
  end

  local names = self:_list_names()
  if #names == 0 then names = { "No configs" } end

  local function update_options(control, options)
    if not control or type(options) ~= "table" or #options == 0 then return false end
    local reference = control.reference or control
    local attempted = false
    if type(ui.update) == "function" then
      local ok = pcall(ui.update, reference, options)
      attempted = ok or attempted
      ok = pcall(ui.update, reference, unpack(options))
      attempted = ok or attempted
    end
    if type(control.update) == "function" then
      local ok = pcall(control.update, control, options)
      attempted = ok or attempted
      ok = pcall(control.update, control, unpack(options))
      attempted = ok or attempted
    end
    return attempted
  end

  update_options(element.list, names)
  if keep and keep ~= "" then
    if self:_is_cloud_selected() then
      for index, item in ipairs(self.cloud_visible_items or {}) do
        if item.key == keep or item.name == keep then
          pcall(element.list.set, element.list, index - 1)
          break
        end
      end
    else
      for index = 1, #names do
        if names[index] == keep then
          pcall(element.list.set, element.list, index - 1)
          break
        end
      end
    end
  end
  pcall(function() self:_update_cloud_info() end)
end

function Class.config:_is_cloud_selected()
  local systems = Class.ui.menu and Class.ui.menu.config_tab and Class.ui.menu.config_tab.config_systems
  if not systems then return false end
  local ok, selected = pcall(systems.get, systems)
  return ok and selected == "Cloud"
end

function Class.config:_cloud_view()
  local control = Class.ui.menu and Class.ui.menu.config_tab and Class.ui.menu.config_tab.cloud_view
  local ok, value = false, "My configs"
  if control then ok, value = pcall(control.get, control) end
  if not ok or type(value) ~= "string" then value = "My configs" end
  return value
end

function Class.config:_list_names()
  if self:_is_cloud_selected() then
    local remote = {}
    for index, item in ipairs(self.cloud_visible_items or {}) do
      remote[index] = item.display or item.name or "Unknown config"
    end
    return remote
  end
  local names = {}
  local seen = {}
  for index = 1, #(self.db.config_presets or {}) do
    local n = self.db.config_presets[index]
    if n and n ~= "" and not seen[n] then
      names[#names + 1] = n
      seen[n] = true
    end
  end
  local extras = {}
  for n, data in pairs(self.db.config_data_local or {}) do
    if type(n) == "string" and n ~= "" and not seen[n] and data ~= nil then
      extras[#extras + 1] = n
      seen[n] = true
    end
  end
  table.sort(extras)
  for i = 1, #extras do names[#names + 1] = extras[i] end
  return names
end

function Class.config:_selected_name()
  if self:_is_cloud_selected() then
    local item = self:_selected_cloud_item()
    return item and item.name or nil
  end
  local element = Class.ui.menu.config_tab
  if not element then return nil end
  local index = 0
  local ok, value = pcall(element.list.get, element.list)
  if ok then index = value or 0 end
  local names = self:_list_names()
  local config_name_local = names[(index or 0) + 1]
  if not config_name_local or config_name_local == "" then return nil end
  return config_name_local
end

function Class.config:_roots()
  return {
   menu = Class.ui.menu,
   states_t = Class.ui.antiaim_conditions_t,
   states_ct = Class.ui.antiaim_conditions_ct,
  }
end
function Class.config:_is_el(v)
  return type(v) == "table" and v._virtual ~= true and type(v.get) == "function" and type(v.set) == "function"
end
function Class.config:_normalize_multi(v)
  if type(v) ~= "table" then return {} end
  local output = {}
  if #v > 0 then
    for index = 1, #v do
      if type(v[index]) == "string" then output[#output + 1] = v[index] end
    end
    if #output > 0 then return output end
  end
  for k, val in pairs(v) do
    if type(k) == "string" and val == true then
      output[#output + 1] = k
    elseif type(val) == "string" then
      output[#output + 1] = val
    end
  end
  return output
end
function Class.config:_read_el(el)
  local success, a, b, c, d = pcall(el.get, el)
  if not success then return nil, false end
  if type(a) == "number" and type(b) == "number" then
    return { "c", a, b, c, d or 255 }, true
  end
  if type(a) == "table" then
    local tr, tg, tb, ta = a[1] or a.r, a[2] or a.g, a[3] or a.b, a[4] or a.a
    if type(tr) == "number" and type(tg) == "number" and type(tb) == "number" then
      return { "c", tr, tg, tb, ta or 255 }, true
    end
    local multi = self:_normalize_multi(a)
    if #multi > 0 or (a and (a[1] ~= nil or next(a) ~= nil)) then
      return { "m", multi }, true
    end
    return { "t", a }, true
  end
  if type(a) == "boolean" then
    return a and 1 or 0, true
  end
  if type(a) == "string" then
    return { "s", a }, true
  end
  return a, true
end
function Class.config:_write_el(el, pack)
  if pack == nil then return end
  pcall(function()
    if type(pack) == "table" then
      if pack[1] == "c" then
        local r, g, b, a = pack[2], pack[3], pack[4], pack[5] or 255
        local ok1 = pcall(el.set, el, r, g, b, a)
        if not ok1 then
          local ok2 = pcall(el.set, el, { r, g, b, a })
          if not ok2 then
            pcall(el.set, el, { r = r, g = g, b = b, a = a })
          end
        end
      elseif pack[1] == "m" then
        el:set(type(pack[2]) == "table" and pack[2] or {})
      elseif pack[1] == "s" then
        el:set(tostring(pack[2] or ""))
      elseif pack[1] == "t" then
        local multi = self:_normalize_multi(pack[2])
        if #multi > 0 or type(pack[2]) == "table" then
          local success = pcall(el.set, el, multi)
          if not success then el:set(pack[2]) end
        else
        el:set(pack[2])
      end
    else
    el:set(pack)
  end
else
if pack == 0 or pack == 1 then
  local success = pcall(el.set, el, pack == 1)
  if not success then el:set(pack) end
else
el:set(pack)
end
end
end)
end
function Class.config:_walk_collect(node, path, output, seen)
  if type(node) ~= "table" then return end
  if seen[node] then return end
  seen[node] = true
  if self:_is_el(node) then
    local pack, success = self:_read_el(node)
    if success then output[path] = pack end
    return
  end
  for k, v in pairs(node) do
    if (type(k) == "string" or type(k) == "number") and not self:_skip_key(k) then
      local nk = path == "" and tostring(k) or (path .. "." .. tostring(k))
      if self:_is_el(v) then
        local pack, success = self:_read_el(v)
        if success then output[nk] = pack end
      elseif type(v) == "table" then
        self:_walk_collect(v, nk, output, seen)
      end
    end
  end
end
function Class.config:_skip_key(k)
  if type(k) ~= "string" then return false end
  if k == "title"
  or k == "home_tab" or k == "config_tab"
  or k == "config_title" or k == "copy_button" or k == "info"
  or k == "config_systems"
  or k == "cloud_endpoint" or k == "cloud_key" or k == "cloud_info"
  or k == "cloud_connect" or k == "cloud_copy_key"
  or k == "cloud_view" or k == "cloud_visibility" or k == "cloud_refresh" or k == "cloud_favorite"
  or k == "cloud_like" or k == "cloud_dislike"
  or k == "brand" or k == "page_selector" or k == "selected_tab"
  or k == "list" or k == "config_name_local" or k == "create" then
    return true
  end
  if k == "button" or k == "load" or k == "save"
  or k == "delete" or k == "import" or k == "export" then
    return true
  end
  if k:find("button", 1, true) then return true end
  return false
end
function Class.config:_get_load_sections()
  local allowed = {"GameSense Settings", "Anti-Aim", "Visuals", "Misc"}
  local control = Class.ui.menu and Class.ui.menu.config_tab and Class.ui.menu.config_tab.load_sections
  if not control then
    local fallback = { ["GameSense Settings"] = true, ["Anti-Aim"] = true, Visuals = true, Misc = true }
    return fallback, #allowed
  end

  local value = nil
  local ok = pcall(function() value = control:get() end)
  if not ok then value = {} end

  local selected = {}
  local values = self:_normalize_multi(value)
  for index = 1, #values do
    local name = values[index]
    if name == "Ragebot" then name = "GameSense Settings" end
    for option = 1, #allowed do
      if name == allowed[option] then
        selected[name] = true
        break
      end
    end
  end

  local count = 0
  for index = 1, #allowed do
    if selected[allowed[index]] then count = count + 1 end
  end
  return selected, count
end

function Class.config:_path_load_enabled(path, selected)
  if path == "menu" then return true end
  if path == "states_t" or path:sub(1, 9) == "states_t." then
    return selected["Anti-Aim"] == true
  end
  if path == "states_ct" or path:sub(1, 10) == "states_ct." then
    return selected["Anti-Aim"] == true
  end

  local branch = path:match("^menu%.([^.]+)")
  if branch == "home_tab" or branch == "config_tab" then return false end
  if branch == "gamesense_settings" then return selected["GameSense Settings"] == true or selected.Ragebot == true end
  if branch == "antiaim_tab" then return selected["Anti-Aim"] == true end
  if branch == "visuals_tab" then return selected.Visuals == true end
  if branch == "misc_tab" then return selected.Misc == true end
  return false
end

function Class.config:_walk_apply(node, path, config_data_local, seen, selected)
  if type(node) ~= "table" or type(config_data_local) ~= "table" then return 0 end
  if not self:_path_load_enabled(path, selected or {}) then return 0 end
  if seen[node] then return 0 end
  seen[node] = true
  local n = 0
  if self:_is_el(node) then
    if config_data_local[path] ~= nil then
      self:_write_el(node, config_data_local[path])
      n = n + 1
    end
    return n
  end
  for k, v in pairs(node) do
    if (type(k) == "string" or type(k) == "number") and not self:_skip_key(k) then
      local nk = path == "" and tostring(k) or (path .. "." .. tostring(k))
      if self:_is_el(v) then
        if config_data_local[nk] ~= nil then
          self:_write_el(v, config_data_local[nk])
          n = n + 1
        end
      elseif type(v) == "table" then
        n = n + self:_walk_apply(v, nk, config_data_local, seen, selected)
      end
    end
  end
  return n
end
function Class.config:_dump()
  if Class.util.viewmodel_store and Class.util.viewmodel_store.save then
    pcall(Class.util.viewmodel_store.save, Class.util.viewmodel_store)
  end
  local pos = nil
  if Class.util.window_pos and Class.util.window_pos.export then
    local ok, value = pcall(Class.util.window_pos.export, Class.util.window_pos)
    if ok then pos = value end
  end
  local flat = {}
  local roots = self:_roots()
  for config_name_local, root in pairs(roots) do
    self:_walk_collect(root, config_name_local, flat, {})
  end
  -- Explicit canonical values for controls that previously shared blank PUI labels.
  pcall(function()
    local ar = Class.ui.menu.visuals_tab.other.aspect_ratio
    local preset_options = { "Custom", "5:4", "4:3", "16:10", "16:9" }
    local preset = ar.preset:get()
    if type(preset) == "number" then
      preset = preset_options[math.floor(preset) + 1] or preset_options[math.floor(preset)]
    end
    local valid_preset = false
    for index = 1, #preset_options do
      if preset == preset_options[index] then
        valid_preset = true
        break
      end
    end
    flat["menu.visuals_tab.other.aspect_ratio.enabled"] = ar.enabled:get() and 1 or 0
    flat["menu.visuals_tab.other.aspect_ratio.preset"] = { "s", valid_preset and preset or "Custom" }
    flat["menu.visuals_tab.other.aspect_ratio.amount"] = tonumber(ar.amount:get()) or 100
  end)
  pcall(function()
    local sh = Class.ui.menu.antiaim_tab.additional.extra
    flat["menu.antiaim_tab.additional.extra.safe_head_enabled"] = sh.safe_head_enabled:get() and 1 or 0
    local conditions = self:_read_el(sh.safe_head.conditions)
    if conditions then flat["menu.antiaim_tab.additional.extra.safe_head.conditions"] = conditions end
    flat["menu.antiaim_tab.additional.extra.safe_head.height_difference"] = tonumber(sh.safe_head.height_difference:get()) or 25
  end)
  pcall(function()
    local screen_width, screen_height = client.screen_size()
    local x, y = Class.util.window_pos:get("wm_x", "wm_y", screen_width * 0.57, screen_height * 0.76)
    flat["menu.visuals_tab.other.watermark.position_x"] = tonumber(x) or math.floor(screen_width * 0.57)
    flat["menu.visuals_tab.other.watermark.position_y"] = tonumber(y) or math.floor(screen_height * 0.76)
  end)
  pcall(function()
    -- Preserve controls with hidden/blank PUI IDs by canonical paths. The
    -- package payload is retained for compatibility, but these values win.
    local logger = Class.ui.menu.misc_tab.event_logger
    flat["menu.misc_tab.event_logger.prefix"] = { "s", tostring(logger.prefix:get() or "") }
    local trigger_control = logger.triggers and logger.triggers.event_triggers
    if trigger_control then
      local trigger_options = { "Aimbot", "Purchase", "Connection problems", "On Screen" }
      local selected = {}
      for index = 1, #trigger_options do
        local option = trigger_options[index]
        local ok, enabled = pcall(trigger_control.get, trigger_control, option)
        if ok and enabled == true then selected[#selected + 1] = option end
      end
      flat["menu.misc_tab.event_logger.triggers.event_triggers"] = { "m", selected }
    end
  end)
  pcall(function()
    flat["menu.visuals_tab.other.watermark.text"] = { "s", tostring(Class.ui.menu.visuals_tab.other.watermark.text:get() or "") }
    local ma = Class.ui.menu.visuals_tab.interface.manual_arrows
    if ma then
      if ma.left then flat["menu.visuals_tab.interface.manual_arrows.left"] = { "s", tostring(ma.left:get() or "") } end
      if ma.right then flat["menu.visuals_tab.interface.manual_arrows.right"] = { "s", tostring(ma.right:get() or "") } end
      if ma.forward then flat["menu.visuals_tab.interface.manual_arrows.forward"] = { "s", tostring(ma.forward:get() or "") } end
    end
  end)
  pcall(function()
    local cs = Class.ui.menu.visuals_tab.interface.custom_scope
    if not cs then return end
    flat["menu.visuals_tab.interface.custom_scope.enabled"] = cs.enabled:get() and 1 or 0
    flat["menu.visuals_tab.interface.custom_scope.mode"] = tostring(cs.mode:get() or "Default")
    flat["menu.visuals_tab.interface.custom_scope.offset.length"] = tonumber(cs.offset.length:get()) or 190
    flat["menu.visuals_tab.interface.custom_scope.offset.gap"] = tonumber(cs.offset.gap:get()) or 15
    if cs.appear_speed then
      flat["menu.visuals_tab.interface.custom_scope.appear_speed"] = tonumber(cs.appear_speed:get()) or 8
    end
    if cs.animate then
      flat["menu.visuals_tab.interface.custom_scope.animate"] = cs.animate:get() and 1 or 0
    end
    if cs.reversed then
      flat["menu.visuals_tab.interface.custom_scope.reversed"] = cs.reversed:get() and 1 or 0
    end
    local c1, c2, c3, c4 = cs.color:get()
    if type(c1) == "table" then
      flat["menu.visuals_tab.interface.custom_scope.color"] = {
       "c", c1[1] or c1.r or 255, c1[2] or c1.g or 255, c1[3] or c1.b or 255, c1[4] or c1.a or 150
      }
    else
    flat["menu.visuals_tab.interface.custom_scope.color"] = {
     "c", tonumber(c1) or 255, tonumber(c2) or 255, tonumber(c3) or 255, tonumber(c4) or 150
    }
  end
end)
pcall(function()
  local notifications = Class.ui.menu.visuals_tab.other.notifications
  local fields = {"lifetime", "max_items"}
  for index = 1, #fields do
    local field = fields[index]
    if notifications and notifications[field] then
      local pack = self:_read_el(notifications[field])
      if pack then flat["menu.visuals_tab.other.notifications." .. field] = pack end
    end
  end
end)
-- Config payloads contain only Lua feature settings. PUI's full-menu package
-- also contains Home / Network controls and menu-specific preferences, so it is
-- deliberately kept out of portable configs. PUI remains used by local UI autosave.
return { f = 8, d = flat, p = pos }
end
function Class.config:_snapshot_tabs()
  local home = Class.ui.menu.home_tab
  local selected_tabs = home.selected_tab
  return {
    page = home.page_selector:get(),
    default = selected_tabs.default:get(),
    antiaim = selected_tabs.antiaim:get(),
    visuals = selected_tabs.visuals:get(),
    miscellaneous = selected_tabs.miscellaneous:get(),
  }
end
function Class.config:_restore_tabs(selected_tabs)
  if type(selected_tabs) ~= "table" then return end
  local home = Class.ui.menu.home_tab
  local tabs = home.selected_tab
  if selected_tabs.page then home.page_selector:set(selected_tabs.page) end
  local page_routes = {
    [MENU_ROUTES.page_home] = MENU_ROUTES.root_home,
    [MENU_ROUTES.page_antiaim] = MENU_ROUTES.root_antiaim,
    [MENU_ROUTES.page_visuals] = MENU_ROUTES.root_visuals,
    [MENU_ROUTES.page_misc] = MENU_ROUTES.root_misc,
  }
  local default_route = page_routes[selected_tabs.page] or selected_tabs.default
  if default_route then tabs.default:set(default_route) end
  if selected_tabs.antiaim then tabs.antiaim:set(selected_tabs.antiaim) end
  if selected_tabs.visuals then tabs.visuals:set(selected_tabs.visuals) end
  local miscellaneous = selected_tabs.miscellaneous or selected_tabs.utilities
  if miscellaneous then tabs.miscellaneous:set(miscellaneous) end
  if Class.ui._sync_nav_tabs then
    pcall(Class.ui._sync_nav_tabs, selected_tabs.default)
  end
end
function Class.config:_apply(config_data_local)
  if type(config_data_local) ~= "table" then return false end

  local sections, section_count = self:_get_load_sections()
  if section_count <= 0 then return false end

  local tabs = self:_snapshot_tabs()
  local applied = 0
  local map = nil

  if type(config_data_local.d) == "table" then
    map = config_data_local.d
  elseif config_data_local.__fmt == "flat" and type(config_data_local.map) == "table" then
    map = config_data_local.map
  elseif type(config_data_local.map) == "table" then
    map = config_data_local.map
  else
    for key in pairs(config_data_local) do
      if type(key) == "string" and key:match("^menu%.") then
        map = config_data_local
        break
      end
    end
  end

  -- Refuse package-only legacy payloads: they serialize the complete native PUI
  -- menu, including Home / Network preferences, and cannot be section-filtered.
  if type(map) ~= "table" then
    self:_restore_tabs(tabs)
    return false
  end

  if (tonumber(config_data_local.f) or 1) < 8 then
    local legacy_ways = { [1] = 3, [2] = 5, [3] = 7, [4] = 9 }
    for path, value in pairs(map) do
      if type(path) == "string" and (path:match("^states_t%.%d+%.yaw%.modifier%.ways$") or path:match("^states_ct%.%d+%.yaw%.modifier%.ways$")) then
        local old_value = tonumber(value)
        if legacy_ways[old_value] then
          map[path] = legacy_ways[old_value]
        end
      end
    end
  end

  local legacy_prefix = "menu.ragebot_tab."
  local current_prefix = "menu.gamesense_settings."
  local feature_aliases = {
    {"hideshots_fix.", "hide_shots_fakelag_fix."},
    {"delay_shot_fix.", "shot_delay_fix."},
    {"dt_bug_fix.", "double_tap_stability_fix."},
    {"animations_flag_fix.", "animation_flag_preservation."},
    {"scan_accuracy.", "scan_accuracy_optimization."},
    {"spread_fix.", "spread_autostop_fix."},
    {"bt_fix.", "backtrack_record_fix."},
    {"backtrack_record_fix.extended_high_lag_records.", "backtrack_record_fix.extended_lag_records."},
    {"backtrack_record_fix.lag_record.", "backtrack_record_fix.lag_records."},
    {"backtrack_record_fix.gap_extended.", "backtrack_record_fix.extended_record_gap."},
    {"backtrack_record_fix.gap.", "backtrack_record_fix.record_gap."},
    {"fakelag.reset_on_shoot_ticks.", "fake_lag.reset_delay_ticks."},
    {"fakelag.reset_on_shoot.", "fake_lag.reset_fake_lag_on_shot."},
    {"fakelag.", "fake_lag."},
  }
  local migrated = {}
  for path, value in pairs(map) do
    if type(path) == "string" then
      local normalized_path = path
      if normalized_path:sub(1, #legacy_prefix) == legacy_prefix then
        normalized_path = current_prefix .. normalized_path:sub(#legacy_prefix + 1)
      end
      if normalized_path:sub(1, #current_prefix) == current_prefix then
        for index = 1, #feature_aliases do
          local alias = feature_aliases[index]
          local relative_path = normalized_path:sub(#current_prefix + 1)
          if relative_path:sub(1, #alias[1]) == alias[1] then
            normalized_path = current_prefix .. alias[2] .. relative_path:sub(#alias[1] + 1)
          end
        end
      end
      if normalized_path ~= path and map[normalized_path] == nil then
        migrated[normalized_path] = value
      end
    end
  end
  for path, value in pairs(migrated) do map[path] = value end

  local function migrate_condition_name(value, use_visible_condition_names)
    if type(value) ~= "string" then return value end
    local normalized = value:gsub("^%s+", ""):gsub("%s+$", "")
    normalized = normalized:gsub("%-", " "):gsub("%s+", " ")
    local lower = normalized:lower()
    if lower == "air crouching" or lower == "air crouch" then
      return use_visible_condition_names and "Air Crouching" or "Air Crouch"
    end
    if lower == "crouching" or lower == "crouch" then
      return use_visible_condition_names and "Crouching" or "Crouch"
    end
    return value
  end

  local function migrate_condition_multiselect(pack, use_visible_condition_names)
    if type(pack) ~= "table" then return end
    local values = pack
    if pack[1] == "m" or pack[1] == "t" then
      values = pack[2]
    end
    if type(values) ~= "table" then return end

    -- Portable configs may store multiselect values as an array, while older
    -- exports can contain a name-to-boolean map. Normalize both representations.
    for index = 1, #values do
      values[index] = migrate_condition_name(values[index], use_visible_condition_names)
    end
    for key, selected in pairs(values) do
      if type(key) == "string" and selected then
        local normalized = migrate_condition_name(key, use_visible_condition_names)
        if normalized ~= key then
          values[normalized] = selected
          values[key] = nil
        end
      end
    end
  end
  local condition_multiselect_paths = {
    {"menu.antiaim_tab.additional.fakelag.anti_bruteforce.conditions", true},
    {"menu.antiaim_tab.additional.hotkey.freestanding_disablers", true},
    {"menu.antiaim_tab.additional.extra.safe_head.conditions", false},
  }
  for index = 1, #condition_multiselect_paths do
    local entry = condition_multiselect_paths[index]
    migrate_condition_multiselect(map[entry[1]], entry[2])
  end

  self._applying = true

  if config_data_local.p and sections.Visuals then
    self:_apply_positions(config_data_local)
  end

  local roots = self:_roots()
  for root_name, root in pairs(roots) do
    applied = applied + self:_walk_apply(root, root_name, map, {}, sections)
  end

  -- Canonical values for controls that previously shared blank PUI labels.
  if sections.Visuals then
    pcall(function()
      local ar = Class.ui.menu.visuals_tab.other.aspect_ratio
      local enabled = map["menu.visuals_tab.other.aspect_ratio.enabled"]
      if enabled ~= nil then
        if type(enabled) == "table" and enabled[1] == "s" then enabled = enabled[2] end
        ar.enabled:set(enabled == 1 or enabled == true or enabled == "1")
      end
      local preset = map["menu.visuals_tab.other.aspect_ratio.preset"]
      if type(preset) == "table" and preset[1] == "s" then preset = preset[2] end
      if type(preset) == "number" then
        local options = { "Custom", "5:4", "4:3", "16:10", "16:9" }
        preset = options[math.floor(preset) + 1] or options[math.floor(preset)]
      end
      local valid_preset = false
      local options = { "Custom", "5:4", "4:3", "16:10", "16:9" }
      for index = 1, #options do
        if preset == options[index] then
          valid_preset = true
          break
        end
      end
      if valid_preset then ar.preset:set(preset) end
      local amount = map["menu.visuals_tab.other.aspect_ratio.amount"]
      if type(amount) == "table" and amount[1] ~= "s" then amount = amount[2] end
      amount = tonumber(amount)
      if amount ~= nil then ar.amount:set(math.max(1, math.min(200, amount))) end
    end)
  end

  if sections.Misc then
    pcall(function()
      local logger = Class.ui.menu.misc_tab.event_logger
      local trigger_control = logger and logger.triggers and logger.triggers.event_triggers
      local saved_triggers = map["menu.misc_tab.event_logger.triggers.event_triggers"]
      if trigger_control and saved_triggers ~= nil then
        local selected
        if type(saved_triggers) == "table" and (saved_triggers[1] == "m" or saved_triggers[1] == "t") then
          selected = self:_normalize_multi(saved_triggers[2])
        else
          selected = self:_normalize_multi(saved_triggers)
        end
        trigger_control:set(selected)
      end
    end)
  end

  if sections["Anti-Aim"] then
    pcall(function()
      local sh = Class.ui.menu.antiaim_tab.additional.extra
      local enabled = map["menu.antiaim_tab.additional.extra.safe_head_enabled"]
      if enabled ~= nil then
        if type(enabled) == "table" and enabled[1] == "s" then enabled = enabled[2] end
        sh.safe_head_enabled:set(enabled == 1 or enabled == true or enabled == "1")
      end
      local conditions = map["menu.antiaim_tab.additional.extra.safe_head.conditions"]
      if type(conditions) == "table" then
        if conditions[1] == "m" or conditions[1] == "t" then
          migrate_condition_multiselect(conditions)
          local selected_conditions = type(conditions[2]) == "table" and conditions[2] or {}
          sh.safe_head.conditions:set(selected_conditions)
        else
          migrate_condition_multiselect(conditions)
          self:_write_el(sh.safe_head.conditions, conditions)
        end
      end
      local height = map["menu.antiaim_tab.additional.extra.safe_head.height_difference"]
      if type(height) == "table" and height[1] ~= "s" then height = height[2] end
      height = tonumber(height)
      if height ~= nil then sh.safe_head.height_difference:set(math.max(-200, math.min(200, height))) end
    end)
  end

  local function set_string(key, element)
    if not element then return end
    local value = map[key]
    if type(value) == "table" and value[1] == "s" then
      pcall(element.set, element, tostring(value[2] or ""))
    elseif type(value) == "string" then
      pcall(element.set, element, value)
    end
  end

  local function set_number(key, element)
    if not element then return end
    local value = map[key]
    if type(value) == "table" and value[1] == "c" then return end
    value = tonumber(value)
    if value ~= nil then pcall(element.set, element, value) end
  end

  if sections.Misc then
    pcall(function()
      set_string("menu.misc_tab.event_logger.prefix", Class.ui.menu.misc_tab.event_logger.prefix)
    end)
  end

  if sections.Visuals then
    pcall(function()
      set_string("menu.visuals_tab.other.watermark.text", Class.ui.menu.visuals_tab.other.watermark.text)
      local arrows = Class.ui.menu.visuals_tab.interface.manual_arrows
      if arrows then
        set_string("menu.visuals_tab.interface.manual_arrows.left", arrows.left)
        set_string("menu.visuals_tab.interface.manual_arrows.right", arrows.right)
        set_string("menu.visuals_tab.interface.manual_arrows.forward", arrows.forward)
      end
    end)

    pcall(function()
      local scope = Class.ui.menu.visuals_tab.interface.custom_scope
      if not scope then return end

      local enabled = map["menu.visuals_tab.interface.custom_scope.enabled"]
      if enabled ~= nil and scope.enabled then
        pcall(scope.enabled.set, scope.enabled, enabled == 1 or enabled == true)
      end

      local mode = map["menu.visuals_tab.interface.custom_scope.mode"]
      if type(mode) == "table" and mode[1] == "s" then mode = mode[2] end
      if mode ~= nil and scope.mode then pcall(scope.mode.set, scope.mode, mode) end

      set_number("menu.visuals_tab.interface.custom_scope.offset.length", scope.offset and scope.offset.length)
      set_number("menu.visuals_tab.interface.custom_scope.offset.gap", scope.offset and scope.offset.gap)

      set_number("menu.visuals_tab.interface.custom_scope.appear_speed", scope.appear_speed)

      local animate = map["menu.visuals_tab.interface.custom_scope.animate"]
      if animate ~= nil and scope.animate then
        pcall(scope.animate.set, scope.animate, animate == 1 or animate == true)
      end

      local reversed = map["menu.visuals_tab.interface.custom_scope.reversed"]
      if reversed == nil and map["menu.visuals_tab.interface.custom_scope.direction"] ~= nil then
        local dir = map["menu.visuals_tab.interface.custom_scope.direction"]
        if type(dir) == "table" and dir[1] == "s" then dir = dir[2] end
        reversed = (dir == "Reversed") and 1 or 0
      end
      if reversed ~= nil and scope.reversed then
        pcall(scope.reversed.set, scope.reversed, reversed == 1 or reversed == true)
      end

      local color = map["menu.visuals_tab.interface.custom_scope.color"]
      if type(color) == "table" and color[1] == "c" and scope.color then
        pcall(scope.color.set, scope.color, color[2], color[3], color[4], color[5] or 150)
      end
    end)

    pcall(function()
      local fields = {"lifetime", "max_items"}
      local other = Class.ui.menu.visuals_tab.other.notifications
      if not other then return end

      for i = 1, #fields do
        local field = fields[i]
        local value = map["menu.visuals_tab.other.notifications." .. field]
        if value == nil then
          value = map["menu.visuals_tab.interface.notifications." .. field]
        end
        if value ~= nil and other[field] then
          self:_write_el(other[field], value)
          applied = applied + 1
        end
      end
    end)
  end

  if sections.Visuals then
    pcall(function()
      if Class.visuals.custom_scope and Class.visuals.custom_scope.reset then
        Class.visuals.custom_scope:reset()
      end
      if Class.util.viewmodel_store and Class.util.viewmodel_store.save then
        Class.util.viewmodel_store:save()
      end
    end)
  end

  -- Keep dedicated text autosave synchronized only when one of its owning
  -- feature sections was loaded. Home / Network controls are never included.
  if sections.Visuals or sections.Misc then
    pcall(function()
      if Class.util.text_state and Class.util.text_state.save then
        Class.util.text_state:save()
      end
    end)
  end

  self._applying = false
  self:_restore_tabs(tabs)
  return applied > 0 or map ~= nil or (config_data_local.p ~= nil and sections.Visuals)
end
function Class.config:_apply_positions(config_data_local)
  if type(config_data_local) ~= "table" then return end
  local pos = config_data_local.p
  if not pos and type(config_data_local) == "table" and config_data_local.notif_x then pos = config_data_local end
  if type(pos) ~= "table" then return end
  if Class.util.window_pos and Class.util.window_pos.import then
    local ok = pcall(Class.util.window_pos.import, Class.util.window_pos, pos)
    if ok and Class.util.window_pos.apply_live then
      pcall(Class.util.window_pos.apply_live, Class.util.window_pos)
    end
  end
end
function Class.config:_encode(config_data_local)
  if type(config_data_local) ~= "table" then return nil end

  local encoded = nil
  if json and json.stringify then
    local ok, value = pcall(json.stringify, config_data_local)
    if ok and type(value) == "string" and value ~= "" then
      encoded = value
    end
  end
  if not encoded then
    local function ser(v, depth)
      depth = depth or 0
      if depth > 14 then return "null" end
      local t = type(v)
      if t == "nil" then return "null" end
      if t == "boolean" then return v and "true" or "false" end
      if t == "number" then
        if v ~= v or v == math.huge or v == -math.huge then return "null" end
        return tostring(v)
      end
      if t == "string" then return string.format("%q", v) end
      if t ~= "table" then return "null" end
      local n = #v
      local is_arr = n > 0
      if is_arr then
        for i = 1, n do
          if v[i] == nil then is_arr = false break end
        end
      end
      if is_arr then
        local parts = {}
        for i = 1, n do parts[i] = ser(v[i], depth + 1) end
        return "[" .. table.concat(parts, ",") .. "]"
      end
      local parts = {}
      for k, val in pairs(v) do
        if type(k) == "string" or type(k) == "number" then
          parts[#parts + 1] = ser(tostring(k), depth + 1) .. ":" .. ser(val, depth + 1)
        end
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
    encoded = ser(config_data_local)
  end

  local config_payload = "8:" .. encoded
  local success, b64 = pcall(base64.encode, config_payload)
  if not success or type(b64) ~= "string" or b64 == "" then return nil end
  b64 = b64:gsub("=+$", "")
  return PREFIX .. b64
end
function Class.config:_decode(text)
  if text == nil then return nil end
  text = tostring(text):gsub("^%s+", ""):gsub("%s+$", "")
  if text == "" then return nil end

  if text:sub(1, 3) == "```" and text:sub(-3) == "```" then
    text = text:sub(4, -4):gsub("^%s+", ""):gsub("%s+$", "")
  end
  if #text >= 2 and ((text:sub(1, 1) == '"' and text:sub(-1) == '"') or
      (text:sub(1, 1) == "'" and text:sub(-1) == "'")) then
    text = text:sub(2, -2)
  end

  local encoded = text
  local accepted_prefixes = { PREFIX, "gothsense_" }
  for index = 1, #accepted_prefixes do
    local prefix = accepted_prefixes[index]
    if encoded:sub(1, #prefix) == prefix then
      encoded = encoded:sub(#prefix + 1)
      break
    end
  end

  local function parse_json(value)
    if not value or value == "" then return nil end
    if json and json.parse then
      local ok, result = pcall(json.parse, value)
      if ok and type(result) == "table" then
        return result
      end
    end
    return nil
  end

  local function unpack_payload(raw_config)
    if type(raw_config) ~= "string" or raw_config == "" then return nil end

    if raw_config:sub(1, 2) == "1:" then
      return { f = 1, d = raw_config:sub(3) }
    end

    if raw_config:sub(1, 2) == "8:" then
      return parse_json(raw_config:sub(3))
    end

    if raw_config:sub(1, 2) == "7:" then
      local compact = raw_config:sub(3)
      for index = 1, #COMPACT_MAP do
        local token = string.char(index)
        if compact:find(token, 1, true) then
          compact = compact:gsub(token, function()
            return COMPACT_MAP[index]
          end)
        end
      end
      local parsed = parse_json(compact)
      if parsed then return parsed end
      return nil
    end

    return parse_json(raw_config)
  end

  local plain = unpack_payload(text)
  if plain then return plain end

  local candidates = { encoded }
  if encoded:find("-", 1, true) or encoded:find("_", 1, true) then
    candidates[#candidates + 1] = encoded:gsub("-", "+"):gsub("_", "/")
  end

  for index = 1, #candidates do
    local candidate = candidates[index]
    candidate = candidate:gsub("%s+", "")
    if candidate ~= "" then
      local pad = #candidate % 4
      if pad > 0 then candidate = candidate .. string.rep("=", 4 - pad) end
      local ok, raw_config = pcall(base64.decode, candidate)
      if ok and type(raw_config) == "string" and raw_config ~= "" then
        local parsed = unpack_payload(raw_config)
        if parsed then return parsed end
      end
    end
  end

  return nil
end
local function cloud_failure_reason(response)
  local status = tonumber(response and response.status) or 0
  local body = type(response and response.body) == "string" and response.body or ""
  body = body:gsub("[%c]", " "):gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
  if #body > 96 then body = body:sub(1, 96) .. "..." end
  if body == "" then body = status == 0 and "network request failed" or "empty response" end
  return "cloud connection failed [" .. tostring(status) .. "]: " .. body
end

local function cloud_url_component(value)
  return (tostring(value or ""):gsub("([^%w%-%_%.%~])", function(char)
    return string.format("%%%02X", string.byte(char))
  end))
end

function Class.config:_cloud_credentials()
  local endpoint = "https://afterglow-cloud.idvampiree.workers.dev"
  local key = ""
  pcall(function() key = tostring(database.read("afterglow.cloud.key.v1") or "") end)
  key = key:gsub("^%s+", ""):gsub("%s+$", "")

  if #key < 32 or #key > 128 then
    local chunks = {}
    for index = 1, 8 do
      local value = 0
      pcall(function() value = tonumber(client.random_int(1, 2147483646)) or 0 end)
      if value <= 0 then
        value = math.floor((tonumber(globals.realtime()) or 0) * 1000000 + index * 104729) % 2147483647
      end
      chunks[index] = string.format("%08x", math.floor(value) % 2147483648)
    end
    key = table.concat(chunks)
    pcall(database.write, "afterglow.cloud.key.v1", key)
  end
  return endpoint, key
end

function Class.config:_cloud_request(method, route, payload, callback)
  local endpoint, key = self:_cloud_credentials()
  if not endpoint or not key then
    if callback then callback(false, { status = 0, body = "Cloud key unavailable" }) end
    return false
  end

  local loaded, http = pcall(require, "gamesense/http")
  if not loaded or type(http) ~= "table" then
    if callback then callback(false, { status = 0, body = "gamesense/http is unavailable" }) end
    return false
  end

  local request = http[string.lower(method or "GET")]
  if type(request) ~= "function" then
    if callback then callback(false, { status = 0, body = "HTTP method unavailable" }) end
    return false
  end

  local options = {
    headers = {
      ["Accept"] = "application/json",
      ["Content-Type"] = "application/json",
      ["Authorization"] = "Bearer " .. key,
    }
  }
  if payload ~= nil then
    local encoded_ok, encoded = pcall(json.stringify, payload)
    if not encoded_ok or type(encoded) ~= "string" then
      if callback then callback(false, { status = 0, body = "JSON encode failed" }) end
      return false
    end
    options.body = encoded
  end

  local finished = false
  local function complete(success, response)
    if finished then return end
    finished = true
    if callback then
      local ok, err = pcall(callback, success == true, response)
      if not ok then
        pcall(cfg_log, nil, "cloud response invalid", true)
      end
    end
  end

  local request_ok = pcall(request, endpoint .. route, options, complete)
  if not request_ok then
    complete(false, { status = 0, body = "HTTP request could not be started" })
    return false
  end
  return true
end

function Class.config:refresh_cloud_list(silent, prefer_name)
  if not self:_is_cloud_selected() then return false end
  local view = self:_cloud_view()
  -- Ignore late responses from a previous view if the user switched lists
  -- again before the request completed.
  self.cloud_refresh_serial = (tonumber(self.cloud_refresh_serial) or 0) + 1
  local request_serial = self.cloud_refresh_serial
  local requested_view = view
  local route
  if view == "My configs" then
    route = "/v1/library"
  else
    local api_view = view == "Favorites" and "favorites" or (view == "Liked" and "liked" or "explore")
    route = "/v1/public?view=" .. api_view
  end

  local previous = prefer_name
  if not previous then
    local current = self:_selected_cloud_item()
    previous = current and current.key or nil
  end

  self:_cloud_request("GET", route, nil, function(success, response)
    if self.cloud_refresh_serial ~= request_serial
      or not self:_is_cloud_selected()
      or self:_cloud_view() ~= requested_view then
      return
    end
    local status = response and tonumber(response.status) or 0
    if not success or status ~= 200 or type(response.body) ~= "string" then
      self.cloud_visible_items = {}
      self:_refresh_list()
      if not silent then cfg_log(nil, cloud_failure_reason(response), true) end
      return
    end

    local parsed_ok, parsed = pcall(json.parse, response.body)
    if not parsed_ok or type(parsed) ~= "table" or type(parsed.configs) ~= "table" then
      self.cloud_visible_items = {}
      self:_refresh_list()
      if not silent then cfg_log(nil, "cloud response invalid", true) end
      return
    end

    local entries, seen = {}, {}
    for _, item in ipairs(parsed.configs) do
      if type(item) == "table" then
        local name = tostring(item.name or "")
        local kind = tostring(item.kind or "public")
        local id = tostring(item.id or "")
        local valid = name ~= "" and #name <= 48 and ((kind == "private") or (kind == "public" and id ~= ""))
        local key = kind == "private" and ("private:" .. name) or ("public:" .. id)
        if valid and not seen[key] then
          seen[key] = true
          local metadata = {
            username = tostring(item.username or "user"):gsub("[%c]", ""):sub(1, 32),
            created_at = tonumber(item.created_at or item.updated_at) or 0,
            likes = tonumber(item.likes) or 0,
            dislikes = tonumber(item.dislikes) or 0,
            my_vote = tonumber(item.my_vote) or 0,
            is_favorite = item.is_favorite == true or tonumber(item.is_favorite) == 1,
            is_owner = item.is_owner == true or tonumber(item.is_owner) == 1,
            kind = kind,
          }
          if metadata.username == "" then metadata.username = "user" end
          entries[#entries + 1] = {
            key = key,
            id = id,
            name = name,
            kind = kind,
            is_owner = metadata.is_owner,
            username = metadata.username,
            created_at = metadata.created_at,
            likes = metadata.likes,
            dislikes = metadata.dislikes,
            my_vote = metadata.my_vote,
            is_favorite = metadata.is_favorite,
            display = cloud_list_display_name(name, metadata),
          }
        end
      end
    end
    if view == "My configs" then
      table.sort(entries, function(a, b)
        if a.kind ~= b.kind then return a.kind == "private" end
        return a.name:lower() < b.name:lower()
      end)
    end
    self.cloud_visible_items = entries
    self:_refresh_list(previous)
    if not silent then cfg_log(nil, "cloud synced") end
  end)
  return true
end

function Class.config:_cloud_create_named()
  local element = Class.ui.menu.config_tab
  local ok, name = pcall(element.name.get, element.name)
  if not ok then name = "" end
  name = tostring(name or ""):gsub("^%s+", ""):gsub("%s+$", "")
  if name == "" then cfg_log(nil, "empty name", true) return end
  if #name > 48 then cfg_log(name, "cloud response invalid", true) return end

  local data = self:_dump()
  local encoded = data and self:_encode(data) or nil
  if not encoded then cfg_log(name, "encode failed", true) return end

  if type(apply_username) == "function" then pcall(apply_username) end
  local username = tostring(user_database and user_database.username or "user"):gsub("[%c]", ""):sub(1, 32)
  if username == "" then username = "user" end
  local visibility = "Private"
  pcall(function()
    visibility = tostring(element.cloud_visibility:get() or "Private")
  end)
  if visibility ~= "Public" then visibility = "Private" end
  local route = visibility == "Public" and "/v1/public" or "/v1/configs"
  self:_cloud_request("POST", route, { name = name, payload = encoded, username = username }, function(success, response)
    local status = response and tonumber(response.status) or 0
    if not success or (status ~= 200 and status ~= 201) then
      cfg_log(name, status == 409 and "cloud name exists" or cloud_failure_reason(response), true)
      return
    end
    cfg_log(name, "cloud created")
    local preferred = visibility == "Public" and ("public:" .. tostring((function()
      local ok_body, body = pcall(json.parse, response.body or "{}")
      return ok_body and body and body.id or ""
    end)())) or ("private:" .. name)
    self:refresh_cloud_list(true, preferred)
  end)
end

function Class.config:_cloud_save_named()
  local item = self:_selected_cloud_item()
  local name = item and item.name or nil
  if not item or not name then cfg_log(nil, "no preset", true) return end
  if not item.is_owner then cfg_log(name, "not your config", true) return end
  local data = self:_dump()
  local encoded = data and self:_encode(data) or nil
  if not encoded then cfg_log(name, "encode failed", true) return end

  if item.kind == "private" then
    local visibility = "Private"
    pcall(function()
      visibility = tostring(Class.ui.menu.config_tab.cloud_visibility:get() or "Private")
    end)
    if visibility == "Public" then
      if type(apply_username) == "function" then pcall(apply_username) end
      local username = tostring(user_database and user_database.username or "user"):gsub("[%c]", ""):sub(1, 32)
      if username == "" then username = "user" end
      self:_cloud_request("POST", "/v1/public", { name = name, payload = encoded, username = username }, function(success, response)
        local status = response and tonumber(response.status) or 0
        if not success or (status ~= 200 and status ~= 201) then
          cfg_log(name, status == 409 and "cloud name exists" or cloud_failure_reason(response), true)
          return
        end
        local id = ""
        local ok_body, body = pcall(json.parse, response.body or "{}")
        if ok_body and type(body) == "table" then id = tostring(body.id or "") end
        cfg_log(name, "cloud created")
        self:refresh_cloud_list(true, id ~= "" and ("public:" .. id) or nil)
      end)
      return
    end
  end

  if item.kind == "public" then
    self:_cloud_request("POST", "/v1/public/" .. cloud_url_component(item.id), { payload = encoded }, function(success, response)
      local status = response and tonumber(response.status) or 0
      if not success or status ~= 200 then
        cfg_log(name, cloud_failure_reason(response), true)
        return
      end
      cfg_log(name, "cloud saved")
      self:refresh_cloud_list(true, item.key)
    end)
  else
    if type(apply_username) == "function" then pcall(apply_username) end
    local username = tostring(user_database and user_database.username or "user"):gsub("[%c]", ""):sub(1, 32)
    if username == "" then username = "user" end
    self:_cloud_request("POST", "/v1/configs/" .. cloud_url_component(name), { payload = encoded, username = username }, function(success, response)
      local status = response and tonumber(response.status) or 0
      if not success or (status ~= 200 and status ~= 201) then
        cfg_log(name, cloud_failure_reason(response), true)
        return
      end
      cfg_log(name, "cloud saved")
      self:refresh_cloud_list(true, item.key)
    end)
  end
end

function Class.config:_cloud_load_selected()
  local _, section_count = self:_get_load_sections()
  if section_count <= 0 then cfg_log(nil, "select sections", true) return end
  local item = self:_selected_cloud_item()
  local name = item and item.name or nil
  if not item or not name then cfg_log(nil, "no preset", true) return end
  local route = item.kind == "public"
    and ("/v1/public/" .. cloud_url_component(item.id))
    or ("/v1/configs/" .. cloud_url_component(name))
  self:_cloud_request("GET", route, nil, function(success, response)
    local status = response and tonumber(response.status) or 0
    if not success or status ~= 200 or type(response.body) ~= "string" then
      cfg_log(name, cloud_failure_reason(response), true)
      return
    end
    local parsed_ok, parsed = pcall(json.parse, response.body)
    if not parsed_ok or type(parsed) ~= "table" or type(parsed.payload) ~= "string" then
      cfg_log(name, "cloud response invalid", true)
      return
    end
    local decode_ok, data = pcall(self._decode, self, parsed.payload)
    if not decode_ok or type(data) ~= "table" then
      cfg_log(name, "invalid data", true)
      return
    end
    local apply_ok, applied = pcall(self._apply, self, data)
    if not apply_ok or not applied then
      cfg_log(name, "apply failed", true)
      return
    end
    pcall(function() self:_apply_positions(data) end)
    pcall(function() Class.util.text_state:save() end)
    cfg_log(name, "cloud loaded")
  end)
end

function Class.config:_cloud_delete_selected()
  local item = self:_selected_cloud_item()
  local name = item and item.name or nil
  if not item or not name then cfg_log(nil, "no preset", true) return end
  if not item.is_owner then cfg_log(name, "not your config", true) return end
  local route = item.kind == "public"
    and ("/v1/public/" .. cloud_url_component(item.id) .. "/delete")
    or ("/v1/delete/" .. cloud_url_component(name))
  self:_cloud_request("POST", route, {}, function(success, response)
    local status = response and tonumber(response.status) or 0
    if not success or status ~= 200 then
      cfg_log(name, cloud_failure_reason(response), true)
      return
    end
    cfg_log(name, "cloud deleted")
    self:refresh_cloud_list(true)
  end)
end

function Class.config:_cloud_toggle_vote(vote)
  local item = self:_selected_cloud_item()
  if not item or item.kind ~= "public" then cfg_log(nil, "select a public config", true) return end
  vote = tonumber(vote) or 0
  local next_vote = item.my_vote == vote and 0 or vote
  self:_cloud_request("POST", "/v1/public/" .. cloud_url_component(item.id) .. "/vote", { vote = next_vote }, function(success, response)
    local status = response and tonumber(response.status) or 0
    if not success or status ~= 200 then
      cfg_log(item.name, cloud_failure_reason(response), true)
      return
    end
    self:refresh_cloud_list(true, item.key)
  end)
end

function Class.config:_cloud_toggle_favorite()
  local item = self:_selected_cloud_item()
  if not item or item.kind ~= "public" then cfg_log(nil, "select a public config", true) return end
  local next_state = not item.is_favorite
  self:_cloud_request("POST", "/v1/public/" .. cloud_url_component(item.id) .. "/favorite", { favorite = next_state }, function(success, response)
    local status = response and tonumber(response.status) or 0
    if not success or status ~= 200 then
      cfg_log(item.name, cloud_failure_reason(response), true)
      return
    end
    self:refresh_cloud_list(true, item.key)
  end)
end

function Class.config:create_named()
  if self:_is_cloud_selected() then return self:_cloud_create_named() end
  local element = Class.ui.menu.config_tab
  local ok, config_name_local = pcall(element.name.get, element.name)
  if not ok then config_name_local = "" end
  config_name_local = tostring(config_name_local or ""):gsub("^%s+", ""):gsub("%s+$", "")
  if config_name_local == "" then
    cfg_log(nil, "empty name", true)
    return
  end
  for index = 1, #self.db.config_presets do
    if self.db.config_presets[index] == config_name_local then
      cfg_log(config_name_local, "already exists", true)
      return
    end
  end
  local config_data_local = self:_dump()
  if config_data_local == nil then
    cfg_log(config_name_local, "no data", true)
    return
  end
  self.db.config_presets[#self.db.config_presets + 1] = config_name_local
  self.db.config_data_local[config_name_local] = config_data_local
  if not self:_write_file() then
    self.db.config_data_local[config_name_local] = nil
    table.remove(self.db.config_presets, #self.db.config_presets)
    self:_refresh_list()
    cfg_log(config_name_local, "write failed", true)
    return
  end
  self:_refresh_list(config_name_local)
  cfg_log(config_name_local, "created")
end
function Class.config:save_named()
  if self:_is_cloud_selected() then return self:_cloud_save_named() end
  local config_name_local = self:_selected_name()
  if not config_name_local then
    cfg_log(nil, "no preset", true)
    return
  end
  local config_data_local = self:_dump()
  if config_data_local == nil then
    cfg_log(config_name_local, "no data", true)
    return
  end
  local previous_data = self.db.config_data_local[config_name_local]
  self.db.config_data_local[config_name_local] = config_data_local
  if not self:_write_file() then
    self.db.config_data_local[config_name_local] = previous_data
    self:_refresh_list(config_name_local)
    cfg_log(config_name_local, "write failed", true)
    return
  end
  self:_refresh_list(config_name_local)
  cfg_log(config_name_local, "saved")
end
function Class.config:load_selected()
  local _, section_count = self:_get_load_sections()
  if section_count <= 0 then cfg_log(nil, "select sections", true) return end
  if self:_is_cloud_selected() then return self:_cloud_load_selected() end
  local config_name_local = self:_selected_name()
  if not config_name_local then
    cfg_log(nil, "no preset", true)
    return
  end
  local config_data_local = self.db.config_data_local[config_name_local]
  if type(config_data_local) == "string" then
    config_data_local = self:_decode(config_data_local)
  end
if config_data_local == nil then
  cfg_log(config_name_local, "invalid data", true)
  return
end
if self:_apply(config_data_local) then
  self:_apply_positions(config_data_local)
  Class.util.text_state:save()
  self:_refresh_list(config_name_local)
  cfg_log(config_name_local, "loaded")
else
cfg_log(config_name_local, "apply failed", true)
end
end
function Class.config:delete_selected()
  if self:_is_cloud_selected() then return self:_cloud_delete_selected() end
  local name = self:_selected_name()
  if not name then
    cfg_log(nil, "no preset", true)
    return
  end
  local removed_index, old_data
  for index = 1, #self.db.config_presets do
    if self.db.config_presets[index] == name then
      removed_index = index
      old_data = self.db.config_data_local[name]
      table.remove(self.db.config_presets, index)
      break
    end
  end
  self.db.config_data_local[name] = nil
  if not removed_index or not self:_write_file() then
    if removed_index then
      table.insert(self.db.config_presets, removed_index, name)
      self.db.config_data_local[name] = old_data
    end
    self:_refresh_list(name)
    cfg_log(name, "write failed", true)
    return
  end
  self:_refresh_list()
  cfg_log(name, "deleted")
end
function Class.config:export_clipboard()
  local tabs = self:_snapshot_tabs()
  local data = self:_dump()
  if data == nil then
    cfg_log(nil, "no data", true)
    self:_restore_tabs(tabs)
    return
  end
  local encoded = self:_encode(data)
  if not encoded then
    cfg_log(nil, "encode failed", true)
    self:_restore_tabs(tabs)
    return
  end
  local success = pcall(clipboard.set, encoded)
  self:_restore_tabs(tabs)
  if not success then
    cfg_log(nil, "clipboard failed", true)
    return
  end
  cfg_log(nil, "exported")
end
function Class.config:import_clipboard()
  local _, section_count = self:_get_load_sections()
  if section_count <= 0 then cfg_log(nil, "select sections", true) return end
  local tabs = nil
  pcall(function() tabs = self:_snapshot_tabs() end)

  local clipboard_success, text = pcall(clipboard.get)
  if not clipboard_success then
    if tabs then self:_restore_tabs(tabs) end
    cfg_log(nil, "clipboard read failed", true)
    return
  end

  text = tostring(text or ""):gsub("^%s+", ""):gsub("%s+$", "")
  if text == "" then
    if tabs then self:_restore_tabs(tabs) end
    cfg_log(nil, "empty clipboard", true)
    return
  end

  local decode_ok, data = pcall(self._decode, self, text)
  if not decode_ok or type(data) ~= "table" then
    if tabs then self:_restore_tabs(tabs) end
    cfg_log(nil, "invalid format", true)
    return
  end

  local apply_ok, applied = pcall(self._apply, self, data)
  if not apply_ok or not applied then
    if tabs then self:_restore_tabs(tabs) end
    cfg_log(nil, "apply failed", true)
    return
  end

  pcall(function() self:_apply_positions(data) end)
  if tabs then self:_restore_tabs(tabs) end
  pcall(function() Class.util.text_state:save() end)
  cfg_log(nil, "imported")
end
function Class.config:handle_storage()
  self:_read_file()
  self:_refresh_list()

  if not self.cloud_info_callback_installed then
    local element = Class.ui.menu and Class.ui.menu.config_tab
    local control = element and element.list
    local reference = control and (control.reference or control)
    local callback = function()
      if Class.config then pcall(Class.config._update_cloud_info, Class.config) end
    end
    if control and type(control.set_callback) == "function" then
      local callback_ok = pcall(control.set_callback, control, callback)
      self.cloud_info_callback_installed = callback_ok
    elseif reference and type(ui.set_callback) == "function" then
      local callback_ok = pcall(ui.set_callback, reference, callback)
      self.cloud_info_callback_installed = callback_ok
    end
  end

  -- Run one delayed refresh after all PUI controls are registered. This is
  -- important for builder comboboxes created before the config subsystem loads.
  if client and type(client.delay_call) == "function" then
    pcall(client.delay_call, 0.25, function()
      if not Class.config then return end
      Class.config:_read_file()
      Class.config:_refresh_list()
    end)
  end
end
end
Class.misc.clan_tag = {
  tag = "afterglow",
  prev = "",
  was_enabled = false,
  frames = nil,

  _glitch_char = function(self, ch)
    local lower = ch:lower()
    if lower == "o" then return "0" end
    if lower == "s" then return "$" end
    if lower == "e" then return "3" end
    if lower == "a" then return "4" end
    if lower == "t" then return "7" end
    if lower == "l" then return "1" end
    if lower == "g" then return "9" end
    return ch
  end,

  _build_frames = function(self)
    local name = self.tag
    local frames = {}
    local n = #name
    local cursor = "|"

    local function push(s)
      frames[#frames + 1] = s
    end

    push("")
    push(cursor)
    push("")
    push(cursor)

    for i = 1, n do
      local plain = name:sub(1, i)
      push(plain .. cursor)
      local last = name:sub(i, i)
      local g = self:_glitch_char(last)
      if g ~= last then
        push(name:sub(1, i - 1) .. g .. cursor)
        push(plain .. cursor)
      end
      push(plain)
    end

    push(name .. cursor)
    push(name)
    push(name .. cursor)
    push(name)

    -- End glitch stays on afterglow only (never old brand names).
    local variants = {
      "afterglow",
      "4fterglow",
      "aft3rglow",
      "aftergl0w",
      "aft3rgl0w",
      "4ft3rgl0w",
      "afterg1ow",
      "aft3rg1ow",
      "4ftergl0w",
      "afterglow",
    }
    for i = 1, #variants do
      push(variants[i])
      push(variants[i] .. cursor)
    end
    for _ = 1, 3 do
      push(name)
      push(name .. cursor)
    end
    push(name)

    for i = n - 1, 0, -1 do
      local part = i > 0 and name:sub(1, i) or ""
      push(part .. cursor)
      push(part)
    end
    push(cursor)
    push("")
    push(cursor)
    push("")

    return frames
  end,

  _get_frame = function(self)
    if not self.frames then
      self.frames = self:_build_frames()
    end
    local interval = globals.tickinterval() or 0.015625
    local latency_ticks = 0
    pcall(function()
      latency_ticks = math.floor(client.latency() / interval + 0.5)
    end)
    local tick = (globals.tickcount() or 0) + latency_ticks
    local speed = math.max(1, math.floor(0.16 / interval + 0.5))
    local idx = math.floor(tick / speed) % #self.frames + 1
    return self.frames[idx]
  end,

  update = function(self)
    local enabled = false
    pcall(function()
      enabled = Class.ui.menu.misc_tab.clan_tag.enabled:get() and true or false
    end)
    if enabled then
      if not self.was_enabled then
        self.frames = nil
        self.prev = ""
      end
      local frame = self:_get_frame()
      if frame ~= self.prev then
        pcall(client.set_clan_tag, frame)
        self.prev = frame
      end
      self.was_enabled = true
    elseif self.was_enabled then
      pcall(client.set_clan_tag, "")
      self.prev = ""
      self.was_enabled = false
    end
  end,

  shutdown = function(self)
    if self.was_enabled then
      pcall(client.set_clan_tag, "")
      self.prev = ""
      self.was_enabled = false
    end
  end,
}

Class.misc.trash_talk = {
 _revenge_userids = {},
 _last_author_preset = {},
 _last_bait_message = nil,
 _next_send_time = 0,

 author_presets = {
  Kill = {
   {"отбитый пидорас", "куда несешься", "спать нахуй"},
   {"что творишь выблядок", "переигран пидор"},
   {"че ты замкадное чепушило", "денег нету да?", "ну тогда на афтерглоу денег не будет"},
   {"никогда не видел", "настолько хуевых как ты", "отдыхай бич"},
   {"ЪАЪАЪАЪАЪА БОМЖАРА", "ЧТО ТВОРИШЬ", "1 СУЧКА"},
   {"что так возбудилась", "спи говно"},
   {"что ты села", "шалава безденежная"},
   {"АФТЕРГЛОУ", "ПЕНИТ ПЕНИТ ПЕНИТ ПЕНИТ"},
   {"куда тебе", "ты нищук слабый", "тебе не понять силу афтерглова"},
   {"бойся", "я опять настигну тебя", "и зарежу как кабельджона нахуй"},
   {"в сон говно", "тихий час наступил"},
   {"говно 1x1 рном", "9 0 проебешь же)))"},
   {"слабак 0 винрейтный", "не тебе меня убивать"},
   {"БУМ НАХУЙ", "К НОГАМ"},
   {"лежать говно", "че приуныло"},
   {"спим", "мать те ебу"},
   {"𝙗𝙞𝙜 𝙚𝙜𝙤", "𝙩𝙞𝙣𝙮 𝙞𝙢𝙥𝙖𝙘𝙩 𖤐 >:("},
   {"𝑨 𝒂𝒇𝒕𝒆𝒓𝒈𝒍𝒐𝒘.𝒚𝒂𝒘 𝒘𝒉𝒐 𝒄𝒖𝒎𝒔", "𝒊𝒏 𝒆𝒗𝒆𝒓𝒚𝒐𝒏𝒆'𝒔 𝒑𝒂𝒔𝒕𝒆 𝒎𝒐𝒖𝒕𝒉."},
   {"your existence is a skill issue"}
  },
  ["Kill Revenge"] = {
   {"111", "бах нахуй"},
   {"куда", "лежим"},
   {"даже наблюдать приятно"},
   {"один минус", "осталось ещё"},
   {"вот это уже похоже на игру"},
   {"хоть кто-то здесь умеет играть ахахаха"},
   {"вс гма играл бтв кста"}
  },
  ["Kill HE"] = {
   {"хаешка нашла цель", "1"},
   {"поймал хае", "анлак"}
  },
  ["Kill Molotov"] = {
   {"молик сработал", "1"},
   {"не стой в огне"}
  },
  ["Kill Knife"] = {
   {"зарезал как кабанчика", "1"},
   {"нож работает", "спи"},
   {"мясник в деле", "вжух"},
   {"подошел вплотную и всё"}
  },
  ["Kill Taser"] = {
   {"тазер в зубы", "1"},
   {"шурупы качественные", "спи"},
   {"разрядился об тебя", "вставай"}
  },
  ["Alive Revenge"] = {
   {"1 сучка", "спи"},
   {"1", "?"},
   {"опа бомжарик упал", "че спим?"},
   {"wp пидор", "АЪАЪАЪА"},
   {"гетни кфг мурзилки"},
   {"а че я твой ник в киллфиде то вижу пидорас"}
  },
  ["Dead Revenge"] = {
   {"наконец-то педик упал", "хуевый"},
   {"1", "изи"},
   {"1", "спи"},
   {"1", "?"},
   {"карма пидорас хуевый хаха"},
   {"КАРМА ГОВНО ЕБАНОЕ", "СПИ ШЛЮХА ХАХАХАХАХА"},
  },
  Death = {
   {"анлак", "в некст раунде отсосешь дик мой"},
   {"не везет", "афтерглоу тебя поставит на колени ща"},
   {"нт бомж", "че как живется с таким везением ебаным", "?"},
   {"блаженный заблевышь"},
   {"как в лц то предиктится тебе?", "А ГОВНО?"},
   {"ой блять моча медленная", "я не пойму как я умираю от таких?"},
   {"понятно хуевый", "я не предикчу"},
   {"FKJ <KZNM","АЛО БЛЯТЬ ТИММЕЙТ КЕРИТЬ БУДЕТ"},
   {"убейся везучий пидор просто"}
  },
 },

 _get_mode = function(self, menu)
  local ok, value = pcall(function() return menu.mode:get() end)
  if ok then
   if value == "Bait" or value == "Author" then return value end
   if type(value) == "number" then
    if value == 0 then return "Bait" end
    if value == 1 then return "Author" end
   end
   local text = tostring(value or ""):lower()
   if text:find("author", 1, true) then return "Author" end
   if text:find("bait", 1, true) then return "Bait" end
  end
  return "Bait"
 end,

 _get_timing = function(self, menu)
  local delay = 0.3
  local interval = 1.2
  pcall(function() delay = (tonumber(menu.delay:get()) or 3) * 0.1 end)
  pcall(function() interval = (tonumber(menu.interval:get()) or 12) * 0.1 end)
  delay = math.max(0.1, math.min(2.0, delay))
  interval = math.max(0.9, math.min(2.9, interval))
  delay = math.floor(delay * 10 + 0.5) / 10
  interval = math.floor(interval * 10 + 0.5) / 10
  return delay, interval
 end,

 _is_selected = function(self, control, event_name)
  local ok, selected = pcall(function() return control:get(event_name) end)
  return ok and selected == true
 end,

 _is_enemy = function(self, player, reference)
  if not player or not reference or player == reference then return false end
  local player_team = tonumber(entity.get_prop(player, "m_iTeamNum")) or 0
  local reference_team = tonumber(entity.get_prop(reference, "m_iTeamNum")) or 0
  return player_team > 1 and reference_team > 1 and player_team ~= reference_team
 end,

 _get_death_event = function(self, weapon)
  -- Every death counts as a plain kill: guns, knife, taser, HE, molotov and
  -- inferno all feed the single "Kill" pool. The spectating remap into
  -- "Kill Revenge" happens in the calling code.
  return "Kill"
 end,

 _record_killer = function(self, attacker_userid, attacker, local_player)
  attacker_userid = tonumber(attacker_userid)
  if not attacker_userid or attacker_userid <= 0 or not attacker or attacker == local_player then return end
  if not self:_is_enemy(attacker, local_player) then return end
  self._revenge_userids[attacker_userid] = true
 end,

 _pick_author_preset = function(self, event_name)
  local presets = self.author_presets[event_name]
  if type(presets) ~= "table" then return nil end

  local available = {}
  for index, preset in ipairs(presets) do
   if type(preset) == "table" then
    local messages = {}
    for _, message in ipairs(preset) do
     if type(message) == "string" then
      message = message:gsub("[%c;]", " "):gsub('"', "'"):gsub("\\", "/")
      message = message:gsub("^%s+", ""):gsub("%s+$", "")
      if message ~= "" then messages[#messages + 1] = message end
     end
    end
    if #messages > 0 and #messages <= 3 then
     available[#available + 1] = {index = index, messages = messages}
    end
   end
  end

  if #available == 0 then return nil end
  local selected = math.random(1, #available)
  local previous = self._last_author_preset[event_name]
  if #available > 1 and previous and available[selected].index == previous then
   selected = selected % #available + 1
  end
  self._last_author_preset[event_name] = available[selected].index
  return available[selected].messages
 end,

 _send_messages = function(self, menu, messages)
  if type(messages) ~= "table" or #messages == 0 then return end
  local delay, interval = self:_get_timing(menu)
  local now = globals.realtime() or 0
  local first_send = math.max(now + delay, tonumber(self._next_send_time) or now)

  for index, message in ipairs(messages) do
   if type(message) == "string" and message ~= "" then
    local scheduled_message = message:gsub("[\r\n]", " "):gsub('"', "'")
    local send_at = first_send + ((index - 1) * interval)
    local wait = math.max(0, send_at - now)
    client.delay_call(wait, function()
     client.exec('say "' .. scheduled_message .. '"')
    end)
   end
  end

  self._next_send_time = first_send + ((#messages - 1) * interval) + 0.25
 end,

 _pick_bait_message = function(self)
  self._last_bait_message = "1"
  return "1"
 end,

 _get_spectator_target = function(self, player)
  local ok, target = pcall(entity.get_prop, player, "m_hObserverTarget")
  if not ok then return nil end
  target = tonumber(target)
  if not target or target <= 0 or not entity.is_alive(target) then return nil end
  return target
 end,

 _is_spectating_enabled = function(self, menu)
  local ok, enabled = pcall(function() return menu.spectator_bait:get() end)
  return ok and enabled == true
 end,

 _send_author_event = function(self, menu, event_name, weapon)
  -- One "Kill" trigger, but weapon-aware messages: HE / molotov / knife /
  -- taser kills have their own phrase pools, everything else falls back to
  -- the generic pool of the event ("Kill" / "Kill Revenge" / ...).
  local messages = nil
  if event_name == "Kill" or event_name == "Kill Revenge" then
   local pool = self:_weapon_kill_pool(weapon)
   if pool then
    messages = self:_pick_author_preset(pool)
   end
  end
  if type(messages) ~= "table" then
   messages = self:_pick_author_preset(event_name)
  end
  self:_send_messages(menu, messages)
 end,

 _weapon_kill_pool = function(self, weapon)
  weapon = tostring(weapon or ""):lower()
  if weapon == "" then return nil end
  if weapon:find("hegrenade", 1, true) then
   return "Kill HE"
  end
  if weapon:find("molotov", 1, true) or weapon:find("inferno", 1, true)
  or weapon:find("incgrenade", 1, true) then
   return "Kill Molotov"
  end
  if weapon:find("knife", 1, true) or weapon:find("bayonet", 1, true) then
   return "Kill Knife"
  end
  if weapon:find("taser", 1, true) then
   return "Kill Taser"
  end
  return nil
 end,

 reset_match = function(self)
  self._revenge_userids = {}
  self._last_bait_message = nil
  self._next_send_time = 0
 end,

 on_player_death = function(self, e)
  local menu = Class.ui.menu.misc_tab.trash_talk
  if not menu or not e then return end
  local enabled_ok, enabled = pcall(function() return menu.enabled:get() end)
  if not enabled_ok or not enabled then return end

  local me = entity.get_local_player()
  if not me then return end

  local victim_userid = tonumber(e.userid)
  local victim = victim_userid and client.userid_to_entindex(victim_userid) or nil
  local attacker_userid = tonumber(e.attacker)
  local attacker = attacker_userid and attacker_userid > 0 and client.userid_to_entindex(attacker_userid) or nil
  if not victim or not victim_userid then return end

  local mode = self:_get_mode(menu)
  local local_alive = entity.is_alive(me)

  if victim == me then
   self:_record_killer(attacker_userid, attacker, me)
   if mode == "Author" and self:_is_selected(menu.triggers, "Death") then
    self:_send_author_event(menu, "Death")
   end
   return
  end

  -- Revenge is independent of whether the local player is alive or dead.
  if self._revenge_userids[victim_userid] then
   self._revenge_userids[victim_userid] = nil
   if mode == "Author" then
    if local_alive and self:_is_selected(menu.triggers, "Revenge") then
     self:_send_author_event(menu, "Alive Revenge")
     return
    elseif not local_alive and self:_is_spectating_enabled(menu)
    and self:_get_spectator_target(me)
    and self:_is_selected(menu.triggers, "Revenge") then
     self:_send_author_event(menu, "Dead Revenge")
     return
    end
   elseif mode == "Bait" then
    if (local_alive or (self:_is_spectating_enabled(menu) and self:_get_spectator_target(me)))
    and self:_is_selected(menu.bait_triggers, "Revenge") then
     self:_send_messages(menu, {"1"})
     return
    end
   end
  end

  if mode == "Bait" then
   local bait_events = menu.bait_triggers
   if local_alive then
    if self:_is_enemy(victim, me) then
     local event_name = self:_get_death_event(e.weapon)
     if self:_is_selected(bait_events, event_name) then
      self:_send_messages(menu, {"1"})
     end
    end
    return
   end

   if not self:_is_spectating_enabled(menu) then return end
   local observed_player = self:_get_spectator_target(me)
   if not observed_player then return end
   if attacker == observed_player and self:_is_enemy(victim, observed_player) then
    local event_name = self:_get_death_event(e.weapon)
    if self:_is_selected(bait_events, event_name) then
     self:_send_messages(menu, {"1"})
    end
   end
   return
  end

  if local_alive then
   if attacker ~= me or not self:_is_enemy(victim, me) then return end
   local event_name = self:_get_death_event(e.weapon)
   if self:_is_selected(menu.triggers, event_name) then
    self:_send_author_event(menu, event_name, e.weapon)
   end
   return
  end

  if not self:_is_spectating_enabled(menu) then return end
  local observed_player = self:_get_spectator_target(me)
  if not observed_player then return end
  if attacker == observed_player and self:_is_enemy(victim, observed_player)
  and self:_is_selected(menu.triggers, "Kill") then
   local event_name = self:_get_death_event(e.weapon)
   if event_name == "Kill" then
    event_name = "Kill Revenge"
   end
   self:_send_author_event(menu, event_name, e.weapon)
  end
 end,
}

do
  Class.misc.optimize_cvars = {
   _active = false,
   _saved = {},
   _applied = {},
   _missing = {},
   _cvars = {
    ["violence_hblood"] = 0,
    ["violence_ablood"] = 0,
    ["violence_hgibs"] = 0,
    ["violence_agibs"] = 0,
    ["cl_ragdoll_physics_enable"] = 0,
    ["ragdoll_sleepaftertime"] = 0,
    ["cl_ragdoll_collide"] = 0,
    ["r_eyemove"] = 0,
    ["r_eyegloss"] = 0,
    ["cl_csm_static_prop_shadows"] = 0,
    ["cl_csm_world_shadows"] = 0,
    ["cl_csm_viewmodel_shadows"] = 0,
    ["r_decals"] = 0,
    ["r_drawmodeldecals"] = 0,
    ["r_maxmodeldecal"] = 1,
    ["mp_decals"] = 5,
    ["r_drawdetailprops"] = 0,
    ["cl_detail_max_sway"] = 0,
    ["r_3dsky"] = 0,
    ["r_dynamic"] = 0,
    ["muzzleflash_light"] = 0,
    ["r_waterforceexpensive"] = 0,
    ["r_waterdrawreflection"] = 0,
    ["r_waterdrawrefraction"] = 0,
    ["cl_show_splashes"] = 0,
    ["rope_smooth"] = 0,
    ["rope_wind_dist"] = 0,
    ["rope_shake"] = 0,
    ["cl_ejectbrass"] = 0,
    ["func_break_max_pieces"] = 0,
    ["r_drawtracers"] = 0,
    ["r_drawtracers_firstperson"] = 0,
    ["cl_disablefreezecam"] = 1,
    ["cl_disablehtmlmotd"] = 1,
    ["cl_autohelp"] = 0,
    ["cl_showhelp"] = 0,
   },
   _profiles = {
    ["Balanced"] = {
     "violence_hblood", "violence_ablood", "violence_hgibs", "violence_agibs",
     "cl_ragdoll_physics_enable", "ragdoll_sleepaftertime", "cl_ragdoll_collide",
     "r_eyemove", "r_eyegloss",
     "r_decals", "r_drawmodeldecals", "r_maxmodeldecal", "mp_decals",
     "r_drawtracers_firstperson", "cl_disablefreezecam", "cl_disablehtmlmotd",
     "cl_autohelp", "cl_showhelp",
    },
    ["Performance"] = {
     "violence_hblood", "violence_ablood", "violence_hgibs", "violence_agibs",
     "cl_ragdoll_physics_enable", "ragdoll_sleepaftertime", "cl_ragdoll_collide",
     "r_eyemove", "r_eyegloss",
     "cl_csm_static_prop_shadows", "cl_csm_world_shadows", "cl_csm_viewmodel_shadows",
     "r_decals", "r_drawmodeldecals", "r_maxmodeldecal", "mp_decals",
     "r_drawdetailprops", "cl_detail_max_sway",
     "r_3dsky", "r_dynamic", "muzzleflash_light",
     "r_waterforceexpensive", "r_waterdrawreflection", "r_waterdrawrefraction", "cl_show_splashes",
     "r_drawtracers", "r_drawtracers_firstperson", "cl_disablefreezecam",
     "cl_disablehtmlmotd", "cl_autohelp", "cl_showhelp",
    },
    ["Maximum FPS"] = {
     "violence_hblood", "violence_ablood", "violence_hgibs", "violence_agibs",
     "cl_ragdoll_physics_enable", "ragdoll_sleepaftertime", "cl_ragdoll_collide",
     "r_eyemove", "r_eyegloss",
     "cl_csm_static_prop_shadows", "cl_csm_world_shadows", "cl_csm_viewmodel_shadows",
     "r_decals", "r_drawmodeldecals", "r_maxmodeldecal", "mp_decals",
     "r_drawdetailprops", "cl_detail_max_sway",
     "r_3dsky", "r_dynamic", "muzzleflash_light",
     "r_waterforceexpensive", "r_waterdrawreflection", "r_waterdrawrefraction", "cl_show_splashes",
     "rope_smooth", "rope_wind_dist", "rope_shake",
     "cl_ejectbrass", "func_break_max_pieces",
     "r_drawtracers", "r_drawtracers_firstperson", "cl_disablefreezecam",
     "cl_disablehtmlmotd", "cl_autohelp", "cl_showhelp",
    },
   },
   _get_variable = function(self, name)
    if self._missing[name] then return nil end
    if type(name) ~= "string" or name == "" then return nil end
    local ok, variable = pcall(function() return cvar[name] end)
    if ok and variable ~= nil then return variable end
    self._missing[name] = true
    return nil
   end,
   _read_variable = function(self, variable)
    if variable == nil then return nil end
    local ok, value = pcall(function() return variable:get_int() end)
    if ok and value ~= nil then return tonumber(value) end
    ok, value = pcall(function() return variable:get_float() end)
    if ok and value ~= nil then return tonumber(value) end
    return nil
   end,
   _write_name = function(self, name, value)
    -- Never use client.exec here: spam = TooManyCommands kick.
    -- Prefer a single set_raw_* write; double set_int/set_float was crashing some builds.
    local number = tonumber(value)
    if number == nil then return false end
    local variable = self:_get_variable(name)
    if variable == nil then return false end
    local integer = math.floor(number + (number >= 0 and 0.5 or -0.5))
    local is_int = math.abs(number - integer) < 0.0001
    local ok = false
    if is_int then
     ok = pcall(function() variable:set_raw_int(integer) end)
     if not ok then ok = pcall(function() variable:set_int(integer) end) end
    else
     ok = pcall(function() variable:set_raw_float(number) end)
     if not ok then ok = pcall(function() variable:set_float(number) end) end
    end
    return ok and true or false
   end,
   _restore_name = function(self, name)
    local saved = self._saved[name]
    if saved == nil then
     self._applied[name] = nil
     return true
    end
    local ok = self:_write_name(name, saved.value)
    self._saved[name] = nil
    self._applied[name] = nil
    return ok
   end,
   _selected = function(self)
    local menu = Class.ui.menu.misc_tab.optimize_cvars
    if not menu then return {} end
    local mode = "Custom"
    if menu.mode then
     pcall(function() mode = menu.mode:get() or "Custom" end)
    end
    local result = {}
    if mode ~= "Custom" then
     local profile = self._profiles[mode] or {}
     for index = 1, #profile do
      result[profile[index]] = true
     end
     return result
    end
    local control = menu.options
    if not control then return result end
    local ok, selected = pcall(function() return control:get() end)
    if not ok or type(selected) ~= "table" then return result end
    for index = 1, #selected do
     if type(selected[index]) == "string" then
      result[selected[index]] = true
     end
    end
    for key, value in pairs(selected) do
     if type(key) == "string" and value then
      result[key] = true
     end
    end
    return result
   end,
   _is_peeking = function(self)
    local me = entity.get_local_player()
    if not me or not entity.is_alive(me) then return false end
    local vx = entity.get_prop(me, "m_vecVelocity[0]")
    local vy = entity.get_prop(me, "m_vecVelocity[1]")
    if type(vx) ~= "number" or type(vy) ~= "number" then
     local ox, oy = entity.get_prop(me, "m_vecVelocity")
     vx, vy = ox, oy
    end
    if type(vx) ~= "number" then return false end
    if type(vy) ~= "number" then vy = 0 end
    return (vx * vx + vy * vy) >= (65 * 65)
   end,
   _should_apply = function(self, menu)
    if not menu or not menu.enabled then return false end
    local enabled = false
    pcall(function() enabled = menu.enabled:get() and true or false end)
    if not enabled then return false end
    local flags = "Always on"
    if menu.flags then
     pcall(function() flags = menu.flags:get() or "Always on" end)
    end
    if flags == "Peeking" then
     return self:_is_peeking()
    end
    return true
   end,
   sync = function(self)
    local menu = Class.ui.menu and Class.ui.menu.misc_tab and Class.ui.menu.misc_tab.optimize_cvars
    local desired = {}
    if menu and self:_should_apply(menu) then
     local selected = self:_selected()
     for name, value in pairs(self._cvars) do
      if selected[name] then
       desired[name] = value
      end
     end
    end

    for name in pairs(self._applied) do
     if desired[name] == nil then
      self:_restore_name(name)
     end
    end

    for name, value in pairs(desired) do
     if self._missing[name] then
      -- skip unknown cvars forever this session
     elseif not self._applied[name] then
      local variable = self:_get_variable(name)
      if variable ~= nil then
       local original = self:_read_variable(variable)
       if original == nil then original = value end
       if self:_write_name(name, value) then
        self._saved[name] = { value = original }
        self._applied[name] = true
       end
      end
     else
      -- only rewrite if value drifted (no exec spam)
      local variable = self:_get_variable(name)
      local current = self:_read_variable(variable)
      local current_number = tonumber(current)
      local target_number = tonumber(value)
      if current_number ~= nil and target_number ~= nil and math.abs(current_number - target_number) > 0.001 then
       self:_write_name(name, value)
      end
     end
    end

    self._active = next(self._applied) ~= nil
   end,
   apply = function(self)
    self:sync()
   end,
   restore = function(self)
    local names = {}
    for name in pairs(self._applied) do
     names[#names + 1] = name
    end
    for index = 1, #names do
     self:_restore_name(names[index])
    end
    self._saved = {}
    self._applied = {}
    self._active = false
   end,
   setup = function(self)
    local menu = Class.ui.menu.misc_tab.optimize_cvars
    if not menu then return end
    if not self._callbacks_bound then
     local function changed()
      self:sync()
     end
     if menu.enabled and menu.enabled.set_callback then menu.enabled:set_callback(changed) end
     if menu.mode and menu.mode.set_callback then menu.mode:set_callback(changed) end
     if menu.options and menu.options.set_callback then menu.options:set_callback(changed) end
     if menu.flags and menu.flags.set_callback then menu.flags:set_callback(changed) end
     client.set_event_callback("level_init", function()
      -- clear missing cache on map change; re-apply once after load
      self._missing = {}
      client.delay_call(0.25, function()
       if Class.misc.optimize_cvars then
        Class.misc.optimize_cvars:sync()
       end
      end)
     end)
     self._callbacks_bound = true
    end
    self:sync()
   end,
  }
end

defer(function()
  if Class.misc.optimize_cvars and Class.misc.optimize_cvars.restore then
    Class.misc.optimize_cvars:restore()
  end
end)


do
  Class.util.break_lc_mem = {
    _base = nil,
    _patch_offs = {},
    _orig = {},
    _active_value = nil,
    _sig = "\x8B\x47\x28\x83\xF8\x10",
    _sig_mask_imm_index = 5,
    _module_size = 13944320,
    _init = function(self)
      if self._base then return true end
      local ok, base = pcall(function()
        local kernel = ffi.load("kernel32")
        if not pcall(ffi.typeof, "GOTH_MODULEENTRY32*") then
          ffi.cdef[[
            typedef void* GOTH_HANDLE;
            typedef unsigned long GOTH_DWORD;
            typedef struct {
              GOTH_DWORD dwSize;
              GOTH_DWORD th32ModuleID;
              GOTH_DWORD th32ProcessID;
              GOTH_DWORD GlblcntUsage;
              GOTH_DWORD ProccntUsage;
              unsigned char* modBaseAddr;
              GOTH_DWORD modBaseSize;
              GOTH_HANDLE hModule;
              char szModule[256];
              char szExePath[260];
            } GOTH_MODULEENTRY32;
            GOTH_HANDLE __stdcall CreateToolhelp32Snapshot(GOTH_DWORD, GOTH_DWORD);
            int __stdcall Module32First(GOTH_HANDLE, GOTH_MODULEENTRY32*);
            int __stdcall Module32Next(GOTH_HANDLE, GOTH_MODULEENTRY32*);
            int __stdcall CloseHandle(GOTH_HANDLE);
            int __stdcall VirtualProtect(void*, size_t, unsigned long, unsigned long*);
          ]]
        end
        local TH32CS_SNAPMODULE = 0x8
        local TH32CS_SNAPMODULE32 = 0x10
        local snap = kernel.CreateToolhelp32Snapshot(bit.bor(TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32), 0)
        if snap == nil or snap == ffi.cast("GOTH_HANDLE", -1) then return nil end
        local entry = ffi.new("GOTH_MODULEENTRY32")
        entry.dwSize = ffi.sizeof("GOTH_MODULEENTRY32")
        local found = nil
        if kernel.Module32First(snap, entry) ~= 0 then
          repeat
            local name = ffi.string(entry.szModule):lower()
            local size = tonumber(entry.modBaseSize) or 0
            if size == self._module_size or name:find("skeet", 1, true) or name:find("gamesense", 1, true) or name:find("csgo", 1, true) == nil and name:find("%.dll") and size > 10000000 and size < 20000000 then
              if size == self._module_size then
                found = entry.modBaseAddr
                break
              end
            end
          until kernel.Module32Next(snap, entry) == 0
        end
        kernel.CloseHandle(snap)
        return found
      end)
      if ok and base ~= nil then
        self._base = base
        self:_scan()
        return #self._patch_offs > 0
      end
      return false
    end,
    _scan = function(self)
      self._patch_offs = {}
      if not self._base then return end
      local ok = pcall(function()
        local text_rva, text_size = 0x1000, 0x1C9A44
        local start = ffi.cast("uint8_t*", self._base) + text_rva
        local sig = self._sig
        local sig_len = #sig
        for i = 0, text_size - sig_len do
          local match = true
          for j = 1, sig_len do
            if start[i + j - 1] ~= sig:byte(j) then
              match = false
              break
            end
          end
          if match then
            self._patch_offs[#self._patch_offs + 1] = text_rva + i + self._sig_mask_imm_index
            if #self._patch_offs >= 4 then break end
          end
        end
      end)
    end,
    set_limit = function(self, value)
      value = math.max(1, math.min(22, math.floor(tonumber(value) or 14)))
      if self._active_value == value then return true end
      if not self:_init() then return false end
      if #self._patch_offs == 0 then return false end
      local ok = pcall(function()
        for idx = 1, #self._patch_offs do
          local addr = ffi.cast("uint8_t*", self._base) + self._patch_offs[idx]
          if self._orig[idx] == nil then
            self._orig[idx] = addr[0]
          end
          local kernel = ffi.load("kernel32")
          local old = ffi.new("unsigned long[1]")
          kernel.VirtualProtect(addr, 1, 0x40, old)
          addr[0] = value
          kernel.VirtualProtect(addr, 1, old[0], old)
        end
      end)
      if ok then
        self._active_value = value
      end
      return ok
    end,
    restore = function(self)
      if not self._base or #self._patch_offs == 0 then return end
      pcall(function()
        for idx = 1, #self._patch_offs do
          if self._orig[idx] ~= nil then
            local addr = ffi.cast("uint8_t*", self._base) + self._patch_offs[idx]
            local kernel = ffi.load("kernel32")
            local old = ffi.new("unsigned long[1]")
            kernel.VirtualProtect(addr, 1, 0x40, old)
            addr[0] = self._orig[idx]
            kernel.VirtualProtect(addr, 1, old[0], old)
          end
        end
      end)
      self._active_value = nil
    end,
  }
end


local function on_startup()
  Class.ui.setup_menu()
  if Class.misc.optimize_cvars and Class.misc.optimize_cvars.setup then
    Class.misc.optimize_cvars:setup()
  end
  if Class.visuals.zoom_animation then Class.visuals.zoom_animation:setup() end
  Class.visuals.watermark_ui:setup()
  if Class.visuals.damage_indicator then Class.visuals.damage_indicator:setup() end
  Class.visuals.velocity_indicator:setup()
  Class.util.text_state:load()
  Class.util.window_pos:bind()
  Class.util.window_pos:apply_live()
  if Class.config and Class.config.handle_storage then Class.config:handle_storage() end
  Class.misc.console_enhancement.console_filter:setup()
  if Class.gamesense.custom_quick_switch then
    Class.gamesense.custom_quick_switch:setup()
  end
  Class.util:hide_menu(false)
end
local function on_shutdown()
  if Class.misc.unlock_hidden_cvars and Class.misc.unlock_hidden_cvars.shutdown then
    pcall(function() Class.misc.unlock_hidden_cvars:shutdown() end)
  end
  if Class.misc.clan_tag and Class.misc.clan_tag.shutdown then
    pcall(function() Class.misc.clan_tag:shutdown() end)
  end
  if Class.misc.discord_rpc and Class.misc.discord_rpc.shutdown then
    pcall(function() Class.misc.discord_rpc:shutdown() end)
  end
  if Class.antiaim and Class.antiaim.extended_yaw and Class.antiaim.extended_yaw.shutdown then
    pcall(function() Class.antiaim.extended_yaw:shutdown() end)
  end
  if Class.antiaim and Class.antiaim.flick_exploit and Class.antiaim.flick_exploit.shutdown then
    pcall(function() Class.antiaim.flick_exploit:shutdown() end)
  end
  if Class.antiaim and Class.antiaim.defensive_aa and Class.antiaim.defensive_aa.shutdown then
    pcall(function() Class.antiaim.defensive_aa:shutdown() end)
  end
  reset_fast_ladder_avoid_state()
  pcall(function()
    if Class.visuals and Class.visuals.animation_breaker then
      Class.visuals.animation_breaker:_restore_animation_state(entity.get_local_player())
      Class.visuals.animation_breaker:_sync_legs_movement(true)
    end
  end)
  pcall(function()
    if Class.util.break_lc_mem and Class.util.break_lc_mem.restore then
      Class.util.break_lc_mem:restore()
    end
  end)
  pcall(function()
    if Class.util and Class.util.text_state and Class.util.text_state.save then
      Class.util.text_state:save()
    end
    if Class.config and Class.config._save_ui_autosave then
      Class.config:_save_ui_autosave()
    end
  end)
  pcall(function()
    if Class.gamesense.accurate_quick_stop and Class.gamesense.accurate_quick_stop.restore then
      Class.gamesense.accurate_quick_stop:restore()
    end
    if Class.gamesense.hide_shots_fakelag_fix and Class.gamesense.hide_shots_fakelag_fix.restore_settings then
      Class.gamesense.hide_shots_fakelag_fix:restore_settings()
    end
    if Class.gamesense.shot_delay_fix and Class.gamesense.shot_delay_fix.restore then
      Class.gamesense.shot_delay_fix:restore()
    end
    if Class.gamesense.double_tap_stability_fix and Class.gamesense.double_tap_stability_fix.restore then
      Class.gamesense.double_tap_stability_fix:restore()
    end
    if Class.gamesense.defensive_double_tap_on_peek then
      Class.gamesense.defensive_double_tap_on_peek:reset()
    end
    if Class.gamesense.double_tap_return_fix and Class.gamesense.double_tap_return_fix.restore then
      Class.gamesense.double_tap_return_fix:restore()
    end
    if Class.gamesense.animation_flag_preservation then Class.gamesense.animation_flag_preservation:restore() end
    if Class.gamesense.air_autostop and Class.gamesense.air_autostop.restore then
      Class.gamesense.air_autostop:restore()
    end
    if Class.gamesense.spread_autostop_fix and Class.gamesense.spread_autostop_fix.restore then
      Class.gamesense.spread_autostop_fix:restore()
    end
    if Class.gamesense.backtrack_record_fix and Class.gamesense.backtrack_record_fix.restore then
      Class.gamesense.backtrack_record_fix:restore()
    end
    if Class.gamesense.force_shot and Class.gamesense.force_shot.restore then
      Class.gamesense.force_shot:restore()
    end
    if Class.gamesense.scan_accuracy_optimization then
      Class.gamesense.scan_accuracy_optimization._shut = true
      if Class.gamesense.scan_accuracy_optimization.restore then
        Class.gamesense.scan_accuracy_optimization:restore()
      end
    end
  end)
  if Class.misc.force_teammate_aimbot and Class.misc.force_teammate_aimbot.restore then
    Class.misc.force_teammate_aimbot.restore()
  end
  Class.util:hide_menu(true)
  if Class.util.set_aa_tab_hidden then
    Class.util:set_aa_tab_hidden(false)
  end
  Class.util:restore_viewmodel()
  if Class.util.remove_sleeves then
    Class.util.remove_sleeves:restore()
  end
  if Class.visuals.opposite_knife_hand and Class.visuals.opposite_knife_hand.shutdown then
    Class.visuals.opposite_knife_hand:shutdown()
  end
  if Class.visuals.lock_bob and Class.visuals.lock_bob.shutdown then
    Class.visuals.lock_bob:shutdown()
  end
  Class.util:reset_console_filter()
  if Class.visuals.custom_scope and Class.visuals.custom_scope.shutdown then
    Class.visuals.custom_scope:shutdown()
  end
  Class.gamesense.custom_quick_switch:shutdown()
  if Class.visuals.zoom_animation and Class.visuals.zoom_animation.shutdown then
    Class.visuals.zoom_animation:shutdown()
  end
end
local MELLSTROY_IMAGE_URL = "https://raw.githubusercontent.com/idvampiree-dot/afterglow-assets/main/bc514b22f9f28b1a97c28a63f25fb775.jpg"
local MELLSTROY_IMAGE_CACHE = "afterglow_mellstroy_photo.jpg"
local MELLSTROY_IMAGE_WIDTH = 735
local MELLSTROY_IMAGE_HEIGHT = 721
local mellstroy_image_texture = nil
local mellstroy_image_bytes = nil
local mellstroy_image_loading = false
local mellstroy_image_requested = false

local function ensure_mellstroy_image()
  if mellstroy_image_texture ~= nil then return end

  if mellstroy_image_bytes ~= nil then
    local ok, texture = pcall(
      renderer.load_jpg,
      mellstroy_image_bytes,
      MELLSTROY_IMAGE_WIDTH,
      MELLSTROY_IMAGE_HEIGHT
    )
    mellstroy_image_bytes = nil
    if ok and texture ~= nil and texture ~= 0 then
      mellstroy_image_texture = tonumber(texture) or texture
      return
    end
  end

  if mellstroy_image_loading or mellstroy_image_requested then return end

  local cache_ok, cached = pcall(readfile, MELLSTROY_IMAGE_CACHE)
  if cache_ok and type(cached) == "string" and #cached > 1000 then
    mellstroy_image_bytes = cached
    return
  end

  mellstroy_image_requested = true
  local http_ok, http = pcall(require, "gamesense/http")
  if not http_ok or type(http) ~= "table" or type(http.get) ~= "function" then
    return
  end

  mellstroy_image_loading = true
  local request_ok = pcall(http.get, MELLSTROY_IMAGE_URL, function(success, response)
    mellstroy_image_loading = false
    if not success or response == nil or response.status ~= 200
      or type(response.body) ~= "string" or #response.body < 1000 then
      return
    end

    mellstroy_image_bytes = response.body
    pcall(writefile, MELLSTROY_IMAGE_CACHE, response.body)
  end)

  if not request_ok then
    mellstroy_image_loading = false
  end
end

local function render_mellstroy_color_grade()
  local control = Class.ui.menu.home_tab and Class.ui.menu.home_tab.mellstroy_mode
  if control == nil or not control:get() then return end

  local screen_w, screen_h = client.screen_size()
  if not screen_w or not screen_h or screen_w <= 0 or screen_h <= 0 then return end

  ensure_mellstroy_image()

  local time = tonumber(globals.realtime()) or 0
  local pulse = (math.sin(time * 1.15) + 1) * 0.5
  local wave = (math.sin(time * 0.53 + 1.1) + 1) * 0.5
  local fast_wave = (math.sin(time * 1.35 + 0.6) + 1) * 0.5
  local hue_a = (math.sin(time * 0.41) + 1) * 0.5
  local hue_b = (math.sin(time * 0.29 + 2.2) + 1) * 0.5
  local screen_mid = math.floor(screen_h * 0.5)

  -- Heavy dual-tone wash: magenta/purple from above, cyan/orange from below.
  renderer.gradient(
    0, 0, screen_w, screen_h,
    255, math.floor(25 + hue_a * 90), math.floor(80 + hue_b * 120), 68 + math.floor(pulse * 18),
    math.floor(20 + hue_b * 90), 0, 255, 62 + math.floor((1 - pulse) * 18),
    true
  )
  renderer.gradient(
    0, 0, screen_w, screen_h,
    math.floor(hue_b * 80), 180, 255, 50 + math.floor(wave * 18),
    255, math.floor(35 + hue_a * 100), math.floor(hue_b * 80), 54 + math.floor((1 - wave) * 16),
    false
  )

  -- Moving center wash and broad colour sweeps.
  local sweep_h = math.max(24, math.floor(screen_h * 0.105))
  local sweep_y = math.floor((time * 145 + screen_h * 0.12) % (screen_h + sweep_h)) - sweep_h
  renderer.gradient(
    0, sweep_y, screen_w, sweep_h,
    255, 28, 120, 8 + math.floor(fast_wave * 17),
    65, 18, 255, 32 + math.floor(pulse * 16),
    true
  )

  local lower_y = math.floor(screen_mid + math.sin(time * 0.9) * screen_h * 0.22)
  renderer.gradient(
    0, lower_y, screen_w, math.max(16, math.floor(screen_h * 0.075)),
    0, 224, 255, 20,
    255, 54, 178, 26 + math.floor(wave * 13),
    true
  )

  -- Six slow glitch ribbons with independent drift; no rapid full-screen flashing.
  for i = 1, 14 do
    local phase = time * (0.22 + i * 0.018) + i * 1.73
    local band_w = math.floor(screen_w * (0.12 + ((math.sin(phase * 0.43) + 1) * 0.5) * 0.68))
    local band_h = math.max(3, math.floor(screen_h * (0.006 + (i % 4) * 0.002)))
    local max_x = math.max(1, screen_w - band_w)
    local x = math.floor(((math.sin(phase) + 1) * 0.5) * max_x)
    local y = math.floor(((math.sin(phase * 0.61 + i) + 1) * 0.5) * (screen_h - band_h))
    local alpha = 18 + math.floor(((math.sin(phase * 0.55) + 1) * 0.5) * 19)
    if i % 3 == 1 then
      renderer.gradient(x, y, band_w, band_h, 255, 34, 132, alpha, 0, 220, 255, alpha, true)
    elseif i % 3 == 2 then
      renderer.gradient(x, y, band_w, band_h, 255, 140, 0, alpha, 94, 20, 255, alpha, true)
    else
      renderer.gradient(x, y, band_w, band_h, 30, 255, 190, alpha, 255, 30, 110, alpha, true)
    end
  end

  -- Scan band and restrained CRT/grid texture.
  local scan_y = math.floor((time * 105) % screen_h)
  local scan_h = math.max(5, math.floor(screen_h * 0.022))
  renderer.gradient(
    0, scan_y, screen_w, scan_h,
    255, 222, 72, 15,
    210, 35, 255, 38,
    true
  )

  local grid_step_x = math.max(48, math.floor(screen_w / 30))
  local grid_step_y = math.max(42, math.floor(screen_h / 22))
  for x = 0, screen_w, grid_step_x do
    renderer.line(x, 0, x, screen_h, 34, 220, 255, 12)
  end
  for y = 0, screen_h, grid_step_y do
    renderer.line(0, y, screen_w, y, 255, 50, 145, 12)
  end

  -- Darkened edges and neon frame make the colour effect read across the whole game view.
  local edge = math.max(24, math.floor(math.min(screen_w, screen_h) * 0.055))
  renderer.gradient(0, 0, screen_w, edge, 5, 0, 16, 82, 5, 0, 16, 0, false)
  renderer.gradient(0, screen_h - edge, screen_w, edge, 5, 0, 16, 0, 5, 0, 16, 82, false)
  renderer.gradient(0, 0, edge, screen_h, 5, 0, 16, 78, 5, 0, 16, 0, true)
  renderer.gradient(screen_w - edge, 0, edge, screen_h, 5, 0, 16, 0, 5, 0, 16, 78, true)

  local frame_alpha = 34 + math.floor(pulse * 20)
  renderer.gradient(0, 0, screen_w, 2, 255, 35, 132, frame_alpha, 0, 210, 255, frame_alpha, true)
  renderer.gradient(0, screen_h - 2, screen_w, 2, 0, 210, 255, frame_alpha, 255, 35, 132, frame_alpha, true)
  renderer.gradient(0, 0, 2, screen_h, 255, 35, 132, frame_alpha, 105, 35, 255, frame_alpha, false)
  renderer.gradient(screen_w - 2, 0, 2, screen_h, 0, 210, 255, frame_alpha, 255, 125, 20, frame_alpha, false)

  if mellstroy_image_texture ~= nil then
    local photo_w = math.floor(math.min(screen_w, screen_h) * 0.235)
    photo_w = math.max(132, math.min(photo_w, 320, screen_w))
    local photo_h = math.floor(photo_w * MELLSTROY_IMAGE_HEIGHT / MELLSTROY_IMAGE_WIDTH)
    photo_h = math.min(photo_h, screen_h)
    local travel_x = math.max(0, screen_w - photo_w)
    local travel_y = math.max(0, screen_h - photo_h)
    local path_x = (math.sin(time * 0.72 + 0.45) + 1) * 0.5
    local path_y = (math.sin(time * 0.91 + 2.15) + 1) * 0.5
    local photo_x = math.floor(path_x * travel_x)
    local photo_y = math.floor(path_y * travel_y)
    local photo_pulse = (math.sin(time * 2.1) + 1) * 0.5
    local photo_alpha = 232 + math.floor(photo_pulse * 23)

    renderer.rectangle(photo_x + 5, photo_y + 6, photo_w, photo_h, 8, 0, 18, 125)
    renderer.rectangle(photo_x - 4, photo_y - 4, photo_w + 8, photo_h + 8, 255, 20, 170, 210)
    renderer.rectangle(photo_x - 2, photo_y - 2, photo_w + 4, photo_h + 4, 0, 220, 255, 220)
    renderer.texture(mellstroy_image_texture, photo_x, photo_y, photo_w, photo_h, 255, 255, 255, photo_alpha)
  end

end

local function on_paint()
  render_mellstroy_color_grade()
  if Class.gamesense.force_shot and Class.gamesense.force_shot.render_indicator then
    Class.gamesense.force_shot:render_indicator()
  end
  Class.visuals.custom_scope:render()
  Class.visuals.aspect_ratio:update()
  Class.visuals.viewmodel_changer:update()
  if Class.util.remove_sleeves then Class.util.remove_sleeves:update() end
  if Class.visuals.opposite_knife_hand then Class.visuals.opposite_knife_hand:update() end
  if Class.visuals.lock_bob then Class.visuals.lock_bob:update() end
end
local function on_paint_ui()
  local record_fix = Class.gamesense.backtrack_record_fix
  if record_fix and next(record_fix._owned) then
    local menu = Class.ui.menu.gamesense_settings.backtrack_record_fix
    if globals.mapname() == nil or not menu.enabled:get() then record_fix:restore() end
  end
  if Class.misc.clan_tag and Class.misc.clan_tag.update then
    Class.misc.clan_tag:update()
  end
  if Class.misc.discord_rpc and Class.misc.discord_rpc.update then
    Class.misc.discord_rpc:update()
  end
  if Class.gamesense.hide_shots_fakelag_fix and Class.gamesense.hide_shots_fakelag_fix.on_paint_ui then
    Class.gamesense.hide_shots_fakelag_fix:on_paint_ui()
  end
  if Class.util.snap_drag then Class.util.snap_drag:begin_frame() end
  Class.ui.update_menu()
  Class.visuals.velocity_indicator:render()
  if Class.visuals.manual_arrows then Class.visuals.manual_arrows:render() end
  if Class.visuals.crosshair_indicator then Class.visuals.crosshair_indicator:render() end
  Class.visuals.watermark_ui:render()
  if Class.visuals.damage_indicator then Class.visuals.damage_indicator:render() end
  Class.render.notifications:render()
  if Class.util.snap_drag then Class.util.snap_drag:draw() end
end
local RESET_FAKE_LAG_ON_SHOT_LEGACY_TICKS = 16
local reset_fake_lag_on_shot_ticks_remaining = 0
local reset_fake_lag_on_shot_ticks_total = RESET_FAKE_LAG_ON_SHOT_LEGACY_TICKS
local reset_fake_lag_on_shot_ticks_elapsed = 0
local reset_fake_lag_on_shot_attack_was_down = false
local reset_fake_lag_on_shot_last_command = nil

local function get_reset_fake_lag_on_shot_ticks()
  local ticks = tonumber(Class.ui.menu.gamesense_settings.fake_lag.reset_delay_ticks:get())
    or RESET_FAKE_LAG_ON_SHOT_LEGACY_TICKS
  ticks = math.max(1, math.min(32, math.floor(ticks)))

  -- Value 16 deliberately keeps the original Reset on Shot timing.
  if ticks == RESET_FAKE_LAG_ON_SHOT_LEGACY_TICKS then
    return RESET_FAKE_LAG_ON_SHOT_LEGACY_TICKS
  end

  return ticks
end

local function clear_reset_fake_lag_on_shot()
  reset_fake_lag_on_shot_ticks_remaining = 0
  reset_fake_lag_on_shot_ticks_total = RESET_FAKE_LAG_ON_SHOT_LEGACY_TICKS
  reset_fake_lag_on_shot_ticks_elapsed = 0
  reset_fake_lag_on_shot_attack_was_down = false
  reset_fake_lag_on_shot_last_command = nil
end

local function arm_reset_fake_lag_on_shot()
  if not Class.ui.menu.gamesense_settings.fake_lag.reset_fake_lag_on_shot:get() then return end
  local ticks = get_reset_fake_lag_on_shot_ticks()
  -- Refresh the window on every detected shot instead of adding to it.
  reset_fake_lag_on_shot_ticks_total = ticks
  reset_fake_lag_on_shot_ticks_elapsed = 0
  reset_fake_lag_on_shot_ticks_remaining = ticks
end

local function on_setup_command(cmd)
  if Class.misc.unlock_hidden_cvars then Class.misc.unlock_hidden_cvars:sync() end
  -- optimize_cvars: only on UI change / level_init (never every tick — causes instability)
  if Class.misc.duck_peek_assist_fix then Class.misc.duck_peek_assist_fix:on_setup_command(cmd) end
  if Class.gamesense.accurate_quick_stop then Class.gamesense.accurate_quick_stop:handle() end
  if Class.gamesense.shot_delay_fix then Class.gamesense.shot_delay_fix:handle() end
  if Class.gamesense.double_tap_stability_fix then Class.gamesense.double_tap_stability_fix:handle() end
  if Class.gamesense.air_autostop then Class.gamesense.air_autostop:handle() end
  if Class.gamesense.scan_accuracy_optimization then Class.gamesense.scan_accuracy_optimization:handle() end
  if Class.gamesense.spread_autostop_fix then Class.gamesense.spread_autostop_fix:handle() end
  if Class.gamesense.backtrack_record_fix then Class.gamesense.backtrack_record_fix:handle() end
  if Class.gamesense.custom_quick_switch then Class.gamesense.custom_quick_switch:tick() end
  if Class.gamesense.force_shot then Class.gamesense.force_shot:handle() end
  if Class.antiaim.anti_bruteforce then Class.antiaim.anti_bruteforce:on_setup_command(cmd) end
  Class.util.antiaim.update_antiaim(cmd)
  if Class.gamesense.double_tap_return_fix then Class.gamesense.double_tap_return_fix:handle() end
  if Class.gamesense.defensive_double_tap_on_peek then Class.gamesense.defensive_double_tap_on_peek:handle(cmd) end
  if Class.gamesense.animation_flag_preservation then Class.gamesense.animation_flag_preservation:handle(Class.ui.menu.gamesense_settings.animation_flag_preservation) end
  if Class.gamesense.hide_shots_fakelag_fix then Class.gamesense.hide_shots_fakelag_fix:handle() end
  -- Reset on Shoot: bypass fakelag for the shot and the configured command window.
  if cmd then
    local enabled = Class.ui.menu.gamesense_settings.fake_lag.reset_fake_lag_on_shot:get()
    if not enabled then
      clear_reset_fake_lag_on_shot()
    else
      local attack_down = cmd.in_attack == 1
      local attack_pressed = attack_down and not reset_fake_lag_on_shot_attack_was_down
      reset_fake_lag_on_shot_attack_was_down = attack_down

      -- Detect the local attack edge immediately; aim_fire and weapon_fire
      -- refresh the window for subsequent and automatic shots.
      if attack_pressed then
        arm_reset_fake_lag_on_shot()
      end

      -- Consume one configured tick per unique command number.
      local command_number = tonumber(cmd.command_number)
      local new_command = command_number == nil or command_number ~= reset_fake_lag_on_shot_last_command
      if command_number ~= nil then
        reset_fake_lag_on_shot_last_command = command_number
      end

      if reset_fake_lag_on_shot_ticks_remaining > 0 then
        -- Apply slider changes to an active window without restarting it.
        -- Elapsed command ticks are preserved; the remaining time is recalculated.
        local configured_ticks = get_reset_fake_lag_on_shot_ticks()
        if configured_ticks ~= reset_fake_lag_on_shot_ticks_total then
          reset_fake_lag_on_shot_ticks_total = configured_ticks
          reset_fake_lag_on_shot_ticks_remaining = math.max(
            0,
            configured_ticks - reset_fake_lag_on_shot_ticks_elapsed
          )
        end

        if reset_fake_lag_on_shot_ticks_remaining > 0 then
          cmd.no_choke = false
          if new_command then
            reset_fake_lag_on_shot_ticks_elapsed = reset_fake_lag_on_shot_ticks_elapsed + 1
            reset_fake_lag_on_shot_ticks_remaining = math.max(
              0,
              reset_fake_lag_on_shot_ticks_total - reset_fake_lag_on_shot_ticks_elapsed
            )
          end
        end
      end
    end
  end
  -- Last in setup_command so builder / other AA writes cannot overwrite the bypass.
  -- Flick is applied inside update_antiaim (builder pipeline) and owns only pitch; extended
  -- yaw keeps driving the fake angle, so the two run independently without fighting over yaw.
  if Class.antiaim.extended_yaw then Class.antiaim.extended_yaw:handle(cmd) end
end
local function on_net_update_start()
  Class.network:update()
  Class.misc.event_logger:on_net_update_start()
end
local function on_aim_fire(e)
  hitrate_shots = hitrate_shots + 1
  Class.util.antiaim._no_flip_until = globals.tickcount() + 14
  arm_reset_fake_lag_on_shot()
  Class.misc.event_logger:on_aim_fire(e)
end
local function on_aim_hit(e)
  hitrate_hits = hitrate_hits + 1
  Class.misc.event_logger:on_aim_hit(e)
end
local function on_aim_miss(e)
  Class.misc.event_logger:on_aim_miss(e)
end
local function on_player_hurt(e)
  Class.misc.event_logger:on_player_hurt(e)
end
local function on_bullet_impact(e)
  Class.misc.event_logger:on_bullet_impact(e)
  Class.antiaim.anti_bruteforce:on_bullet_impact(e)
end
local function on_item_purchase(e)
  Class.misc.event_logger:on_item_purchase(e)
end
local function on_client_disconnect()
  if Class.misc.trash_talk then Class.misc.trash_talk:reset_match() end
  if Class.gamesense.accurate_quick_stop then
    pcall(function() Class.gamesense.accurate_quick_stop:restore() end)
  end
  if Class.gamesense.defensive_double_tap_on_peek then pcall(function() Class.gamesense.defensive_double_tap_on_peek:reset() end) end
  if Class.gamesense.double_tap_return_fix then pcall(function() Class.gamesense.double_tap_return_fix:restore() end) end
  if Class.gamesense.animation_flag_preservation then pcall(function() Class.gamesense.animation_flag_preservation:restore() end) end
  if Class.gamesense.force_shot then pcall(function() Class.gamesense.force_shot:restore() end) end
  clear_reset_fake_lag_on_shot()
  reset_fast_ladder_avoid_state()
  local logger = Class.ui.menu.misc_tab.event_logger
  local log_connection = logger and logger.enabled:get() and logger.triggers.event_triggers:get("Connection problems")

  Class.util.antiaim.clear_data()
  Class.render.notifications:clear()
  Class.network.last_ping = nil
  Class.network.high_ping = false
  Class.network.high_loss = false

  if log_connection then
    local accent = {255, 0, 0}
    Class.misc.event_logger:_emit(accent, {240, 240, 240}, {
     {text = "Connection problem ", color = {240, 240, 240}},
     {text = "detected", color = accent},
    })
    if logger.triggers.event_triggers:get("On Screen") then
      Class.render.notifications:push(
        "/rConnection problem /vdetected/r",
        "connection"
      )
    end
  end
end
local function on_level_init()
  if Class.misc.trash_talk then Class.misc.trash_talk:reset_match() end
  if Class.gamesense.accurate_quick_stop then
    pcall(function() Class.gamesense.accurate_quick_stop:restore() end)
  end
  if Class.gamesense.defensive_double_tap_on_peek then pcall(function() Class.gamesense.defensive_double_tap_on_peek:reset() end) end
  if Class.gamesense.double_tap_return_fix then pcall(function() Class.gamesense.double_tap_return_fix:restore() end) end
  if Class.gamesense.animation_flag_preservation then pcall(function() Class.gamesense.animation_flag_preservation:restore() end) end
  if Class.gamesense.force_shot then pcall(function() Class.gamesense.force_shot:restore() end) end
  clear_reset_fake_lag_on_shot()
  reset_fast_ladder_avoid_state()
  Class.render.notifications:clear()
  Class.util.antiaim.clear_data()
  Class.util.antiaim.reenable()
  Class.misc.console_enhancement.console_cleaner:on_level_init()
end
local function on_round_prestart()
  clear_reset_fake_lag_on_shot()
  Class.render.notifications:clear()
  Class.util.antiaim.clear_data()
  Class.util.antiaim.reenable()
  local console = Class.ui.menu.misc_tab.console_enhancement
  local mode = console and console.mode
  if mode then
    local selected = mode:get()
    if selected == "Clean On New Round" then
      client.exec("clear")
    end
  end
end
on_startup()
client.set_event_callback("setup_command", on_setup_command)
local function on_finish_command(cmd)
  Class.visuals.animation_breaker:update(cmd)
end
client.set_event_callback("finish_command", on_finish_command)
client.set_event_callback("net_update_start", on_net_update_start)
client.set_event_callback("level_init", on_level_init)
client.set_event_callback("client_disconnect", on_client_disconnect)
client.set_event_callback("round_prestart", on_round_prestart)
client.set_event_callback("player_spawn", function(e)
  local lp = entity.get_local_player()
  if not lp then return end
  if client.userid_to_entindex(e.userid) == lp then
    Class.util.antiaim.clear_data()
    Class.util.antiaim.reenable()
  end
end)
client.set_event_callback("shutdown", on_shutdown)
client.set_event_callback("bullet_impact", on_bullet_impact)
client.set_event_callback("aim_fire", on_aim_fire)
client.set_event_callback("aim_hit", on_aim_hit)
client.set_event_callback("aim_miss", on_aim_miss)
local function on_player_death(e)
  Class.antiaim.anti_bruteforce:on_player_death(e)
  if Class.misc.trash_talk then Class.misc.trash_talk:on_player_death(e) end
end
client.set_event_callback("player_hurt", on_player_hurt)
client.set_event_callback("player_death", on_player_death)
client.set_event_callback("item_purchase", on_item_purchase)
client.set_event_callback("player_say", function(e)
  Class.misc.enemy_chat_viewer:on_player_say(e)
end)
client.set_event_callback("player_chat", function(e)
  Class.misc.enemy_chat_viewer:on_player_chat(e)
end)
client.set_event_callback("grenade_thrown", function(e)
  Class.gamesense.custom_quick_switch:on_grenade_thrown(e)
end)
local function on_post_update_clientside_animation()
  Class.visuals.animation_breaker:on_post_update_clientside_animation()
end
client.set_event_callback("post_update_clientside_animation", on_post_update_clientside_animation)
client.set_event_callback("weapon_fire", function(e)
  local local_player = entity.get_local_player()
  if local_player and e and e.userid and client.userid_to_entindex(e.userid) == local_player then
    Class.util.antiaim._no_flip_until = globals.tickcount() + 14
    -- Server event fallback: do not restart a window already armed locally.
    if reset_fake_lag_on_shot_ticks_remaining <= 0 then
      arm_reset_fake_lag_on_shot()
    end
  end
  Class.gamesense.custom_quick_switch:on_weapon_fire(e)
end)
client.set_event_callback("paint", on_paint)
client.set_event_callback("paint_ui", on_paint_ui)
client.set_event_callback("paint_ui", function()
  Class.ui.align_root_nav_buttons()
  Class.ui.align_event_logger_controls()
  Class.ui.align_manual_arrows_controls()
  Class.ui.align_extended_yaw_bind()
  Class.ui.align_visuals_and_config()
  Class.ui.align_builder_action_buttons()
  Class.ui.align_footer_to_menu_bottom_left()
end)
